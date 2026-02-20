"""Product routes — list, add, detail, delete."""

from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash
from web.auth import login_required, role_required
from web.services import get_registry, get_search_engine
from tracker.product import Product, ProductCategory, LicenceType, SupportStatus

bp = Blueprint("products", __name__)


def _parse_date(val):
    if not val:
        return None
    try:
        return datetime.strptime(val, "%Y-%m-%d")
    except ValueError:
        return None


@bp.route("/")
@login_required
def list_products():
    registry = get_registry()
    category = request.args.get("category")
    vendor = request.args.get("vendor")
    status = request.args.get("status")
    environment = request.args.get("environment")
    q = request.args.get("q")

    if q:
        search = get_search_engine(registry)
        cat = ProductCategory(category) if category else None
        st = SupportStatus(status) if status else None
        results = search.search(
            query=q, category=cat, vendor=vendor or None,
            status=st, environment=environment or None,
        )
        products = [r.product for r in results]
    elif category:
        products = registry.by_category(ProductCategory(category))
    elif vendor:
        products = registry.by_vendor(vendor)
    elif status:
        products = registry.by_status(SupportStatus(status))
    elif environment:
        products = registry.by_environment(environment)
    else:
        products = registry.list_all()

    all_products = registry.list_all()
    vendors = sorted(set(p.vendor for p in all_products))
    environments = sorted(set(p.environment for p in all_products))

    from web.sort_utils import sort_items
    products, sort_field, sort_order = sort_items(
        products,
        request.args.get("sort"),
        request.args.get("order"),
        {
            "name": lambda p: (p.name or "").lower(),
            "vendor": lambda p: (p.vendor or "").lower(),
            "version": lambda p: (p.version or "").lower(),
            "category": lambda p: p.category.value,
            "status": lambda p: p.support_status().value,
            "expiry": lambda p: p.days_until_licence_expiry() if p.days_until_licence_expiry() is not None else 999999,
            "cost": lambda p: p.annual_cost or 0,
            "environment": lambda p: (p.environment or "").lower(),
        },
    )

    return render_template(
        "products/list.html",
        products=products,
        vendors=vendors,
        environments=environments,
        filters={"category": category, "vendor": vendor, "status": status,
                 "environment": environment, "q": q},
        sort_field=sort_field,
        sort_order=sort_order,
    )


@bp.route("/add", methods=["GET", "POST"])
@role_required("admin", "editor")
def add_product():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        vendor = request.form.get("vendor", "").strip()
        version = request.form.get("version", "").strip()
        if not name or not vendor or not version:
            flash("Name, Vendor, and Version are required.", "danger")
            return redirect(url_for("products.add_product"))

        try:
            category = ProductCategory(request.form.get("category", "other"))
        except ValueError:
            flash("Invalid category.", "danger")
            return redirect(url_for("products.add_product"))

        registry = get_registry()
        tags = [t.strip() for t in request.form.get("tags", "").split(",") if t.strip()]
        product = Product(
            name=name,
            vendor=vendor,
            version=version,
            category=category,
            licence_type=LicenceType(request.form.get("licence_type", "subscription")),
            licence_key=request.form.get("licence_key", ""),
            licence_quantity=int(request.form.get("licence_quantity", 1)),
            licence_expiry=_parse_date(request.form.get("licence_expiry")),
            mainstream_support_end=_parse_date(request.form.get("mainstream_support_end")),
            extended_support_end=_parse_date(request.form.get("extended_support_end")),
            end_of_life=_parse_date(request.form.get("end_of_life")),
            annual_cost=float(request.form.get("annual_cost") or 0),
            environment=request.form.get("environment", "production"),
            department=request.form.get("department", ""),
            owner=request.form.get("owner", ""),
            notes=request.form.get("notes", ""),
            tags=tags,
        )
        registry.add(product)
        flash(f"Product '{product.name}' added successfully.", "success")
        return redirect(url_for("products.list_products"))
    return render_template("products/add.html")


@bp.route("/<product_id>")
@login_required
def detail(product_id):
    registry = get_registry()
    product = registry.get(product_id)
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("products.list_products"))
    return render_template("products/detail.html", product=product)


@bp.route("/<product_id>/delete", methods=["GET", "POST"])
@role_required("admin", "editor")
def delete_product(product_id):
    if request.method == "GET":
        return redirect(url_for("products.list_products"))
    registry = get_registry()
    if registry.remove(product_id):
        flash("Product removed.", "success")
    else:
        flash("Product not found.", "danger")
    return redirect(url_for("products.list_products"))
