import csv
import os
import logging
from itertools import groupby

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Table, TableStyle

from db import DatabaseManager

logger = logging.getLogger(__name__)

def export_to_csv(report, filename="unused_policies.csv", dir="reports"):
    """
    Export the unused policies report to a CSV file.

    :param report: List of dictionaries containing policy information
    :param filename: Name of the CSV file to create
    """
    if not os.path.exists(dir):
        os.makedirs(dir)
    save_file = os.path.join(dir, filename)

    db_manager = DatabaseManager()

    # Get all possible rule detail keys
    all_rule_detail_keys = set()
    for policy in report:
        if policy["rule_details"]:
            rule_details = db_manager.unpack_rule_details(policy["rule_details"])
            all_rule_detail_keys.update(rule_details.keys())

    fieldnames = [
        "Firewall",
        "Policy",
        "Last Seen Unused",
        "First Seen Unused",
        "Days Since Last Import",
        "Total Days Unused",
    ] + list(all_rule_detail_keys)

    with open(save_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for policy in report:
            row = {
                "Firewall": policy["Firewall"],
                "Policy": policy["Policy"],
                "Last Seen Unused": policy["Last Seen Unused"],
                "First Seen Unused": policy["First Seen Unused"],
                "Days Since Last Import": policy["Days Since Last Import"],
                "Total Days Unused": policy["Total Days Unused"],
            }
            if policy["rule_details"]:
                rule_details = db_manager.unpack_rule_details(policy["rule_details"])
                row.update(rule_details)
            writer.writerow(row)
    
    logger.info(f"CSV report exported to {save_file}")


def generate_pdf_report(report, filename="unused_policies_report.pdf", dir="reports"):
    """
    Generate a PDF report of the unused policies, with each firewall starting on a new page.

    :param report: List of dictionaries containing policy information
    :param filename: Name of the PDF file to create
    """
    if not os.path.exists(dir):
        os.makedirs(dir)
    save_file = os.path.join(dir, filename)
    doc = SimpleDocTemplate(
        save_file,
        pagesize=landscape(letter),
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )
    elements = []

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading1"]
    normal_style = styles["Normal"]

    # Create a custom style for table headers
    header_style = ParagraphStyle(
        "HeaderStyle",
        parent=styles["Normal"],
        fontSize=12,
        leading=14,
        alignment=1,  # Center alignment
        textColor=colors.whitesmoke,
        backColor=colors.grey,
    )

    # Create a custom style for table data
    data_style = ParagraphStyle(
        "DataStyle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=1,  # Center alignment
    )

    elements.append(Paragraph("Unused Policies Report", title_style))
    elements.append(
        Paragraph("The following policies have been flagged for removal:", normal_style)
    )
    elements.append(Paragraph("", normal_style))  # Add some space

    # Group the policies by firewall
    sorted_report = sorted(report, key=lambda x: x["Firewall"])
    grouped_report = groupby(sorted_report, key=lambda x: x["Firewall"])

    db_manager = DatabaseManager()

    for firewall, policies in grouped_report:
        elements.append(Paragraph(f"Firewall: {firewall}", heading_style))

        # Create the data for the table
        headers = [
            "Policy",
            "Last Seen Unused",
            "First Seen Unused",
            "Days Since Last Import",
            "Total Days Unused",
        ]

        # Add rule detail headers
        rule_detail_headers = set()
        for policy in policies:
            if policy["rule_details"]:
                rule_details = db_manager.unpack_rule_details(policy["rule_details"])
                rule_detail_headers.update(rule_details.keys())
        
        headers.extend(sorted(rule_detail_headers))

        data = [[Paragraph(header, header_style) for header in headers]]

        for policy in policies:
            row = [
                Paragraph(policy["Policy"], data_style),
                Paragraph(policy["Last Seen Unused"], data_style),
                Paragraph(policy["First Seen Unused"], data_style),
                Paragraph(str(policy["Days Since Last Import"]), data_style),
                Paragraph(str(policy["Total Days Unused"]), data_style),
            ]

            # Add rule details
            if policy["rule_details"]:
                rule_details = db_manager.unpack_rule_details(policy["rule_details"])
                for header in rule_detail_headers:
                    value = rule_details.get(header, "")
                    row.append(Paragraph(str(value), data_style))
            else:
                row.extend([Paragraph("", data_style) for _ in rule_detail_headers])

            data.append(row)

        # Create the table
        col_widths = [1.5 * inch] + [0.8 * inch] * (len(headers) - 1)
        table = Table(data, colWidths=col_widths)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )

        elements.append(table)
        elements.append(PageBreak())

    doc.build(elements)
    logger.info(f"PDF report generated at {save_file}")
