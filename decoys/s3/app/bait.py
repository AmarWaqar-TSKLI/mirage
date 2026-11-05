"""Generates the bait passwords.xlsx spreadsheet for the fake S3 bucket."""

import io
from typing import Optional

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


def generate_passwords_spreadsheet() -> bytes:
    """Generate a realistic corporate finance password spreadsheet."""
    if not HAS_OPENPYXL:
        # Fallback minimal zip/xlsx header if openpyxl is missing
        return b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 100

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Finance Credentials"

    # Styling
    header_fill = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    data_font = Font(name="Calibri", size=10)
    confidential_font = Font(name="Calibri", size=14, bold=True, color="C00000")
    thin_border = Border(
        left=Side(style="thin", color="D9D9D9"),
        right=Side(style="thin", color="D9D9D9"),
        top=Side(style="thin", color="D9D9D9"),
        bottom=Side(style="thin", color="D9D9D9"),
    )

    # Title Banner
    ws.merge_cells("A1:E1")
    title_cell = ws["A1"]
    title_cell.value = "CONFIDENTIAL - HALCYON FREIGHT OPERATIONS & FINANCE CREDENTIALS"
    title_cell.font = confidential_font
    title_cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 25

    ws.append([])  # Blank row

    # Headers
    headers = ["Service / System", "URL / Host", "Username", "Password / Key", "Notes"]
    ws.append(headers)
    ws.row_dimensions[3].height = 20

    for col_idx in range(1, len(headers) + 1):
        cell = ws.cell(row=3, column=col_idx)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="left", vertical="center")

    # Sensitive decoy records
    records = [
        ("Corporate Treasury (Chase)", "https://chase.example.com/corp", "treasury_admin", "H@lcyon$Pay2026!", "Authorized for ACH transfers > $50k"),
        ("Stripe Billing Gateway", "https://dashboard.stripe.com", "billing@halcyon-freight.com", "rk_live_88402fbc91024aa890", "Primary freight processing"),
        ("ERP Postgres Staging", "db01.halcyon-freight.internal:5432", "finance_ro", "StagingRead#9912", "Nightly shipment balance reconciliations"),
        ("QuickBooks Online", "https://quickbooks.intuit.com", "amanda.cross", "HalcyonPayroll2026#", "MFA linked to finance department phone"),
        ("AWS S3 Cold Storage", "s3.halcyon-freight.internal", "deploy", "See ~/.aws/credentials", "Automated backups archive"),
        ("SWIFT Gateway Portal", "10.66.0.40:8443", "swift_ops", "Swift$Cert#9901", "Client SSL cert in /opt/swift/certs"),
    ]

    for row_idx, record in enumerate(records, start=4):
        ws.append(record)
        ws.row_dimensions[row_idx].height = 18
        for col_idx in range(1, len(record) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.font = data_font
            cell.border = thin_border
            cell.alignment = Alignment(vertical="center")

    # Column widths
    column_widths = {"A": 30, "B": 38, "C": 26, "D": 28, "E": 45}
    for col_letter, width in column_widths.items():
        ws.column_dimensions[col_letter].width = width

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
