import csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from itertools import groupby
import os


def export_to_csv(report, filename="unused_policies.csv", dir="reports"):
    """
    Export the unused policies report to a CSV file.

    :param report: List of dictionaries containing policy information
    :param filename: Name of the CSV file to create
    """
    if not os.path.exists(dir):
        os.makedirs(dir)
    save_file = os.path.join(dir, filename)
    with open(save_file, "w", newline="") as csvfile:
        fieldnames = [
            "Firewall",
            "Policy",
            "Last Seen Unused",
            "First Seen Unused",
            "Days Since Last Import",
            "Total Days Unused",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for policy in report:
            writer.writerow(policy)


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
        data = [[Paragraph(header, header_style) for header in headers]]

        for policy in policies:
            data.append(
                [
                    Paragraph(policy["Policy"], data_style),
                    Paragraph(policy["Last Seen Unused"], data_style),
                    Paragraph(policy["First Seen Unused"], data_style),
                    Paragraph(str(policy["Days Since Last Import"]), data_style),
                    Paragraph(str(policy["Total Days Unused"]), data_style),
                ]
            )

        # Create the table
        table = Table(
            data, colWidths=[6 * inch, 0.9 * inch, 0.9 * inch, 0.7 * inch, 0.7 * inch]
        )
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
