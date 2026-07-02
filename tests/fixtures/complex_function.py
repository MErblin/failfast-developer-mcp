"""Test fixture: Overly complex functions.

This file deliberately contains functions with high cyclomatic complexity
for testing the ComplexityAnalyzer.
"""
# ruff: noqa
# type: ignore


def process_order(order: dict) -> str:
    """Deliberately complex function with CC > 15.

    This function has way too many branches and should be flagged.
    """
    status = order.get("status", "unknown")
    payment = order.get("payment_method", "unknown")
    amount = order.get("amount", 0)
    customer_type = order.get("customer_type", "regular")
    region = order.get("region", "us")
    has_discount = order.get("has_discount", False)

    if status == "pending":
        if payment == "credit_card":
            if amount > 10000:
                if customer_type == "vip":
                    return "manual_review"
                elif customer_type == "enterprise":
                    return "auto_approve_with_limit"
                else:
                    return "manual_review"
            elif amount > 1000:
                if has_discount:
                    return "apply_discount_and_process"
                else:
                    return "auto_approve"
            else:
                return "auto_approve"
        elif payment == "wire_transfer":
            if region == "us":
                return "domestic_wire"
            elif region == "eu":
                return "international_wire_eu"
            elif region == "asia":
                if amount > 50000:
                    return "compliance_review"
                else:
                    return "international_wire_asia"
            else:
                return "international_wire_other"
        elif payment == "crypto":
            if amount > 5000:
                return "compliance_review"
            else:
                return "crypto_process"
        else:
            return "unsupported_payment"
    elif status == "processing":
        if payment == "credit_card":
            return "check_payment_gateway"
        else:
            return "check_bank_transfer"
    elif status == "shipped":
        return "track_shipment"
    elif status == "cancelled":
        if payment == "credit_card":
            return "refund_card"
        elif payment == "wire_transfer":
            return "refund_wire"
        else:
            return "refund_other"
    else:
        return "unknown_status"


def simple_function(x: int) -> int:
    """Low complexity function — should NOT be flagged."""
    if x > 0:
        return x * 2
    return 0
