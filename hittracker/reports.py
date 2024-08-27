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
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from itertools import groupby


def export_to_csv(report, filename="unused_policies.csv"):
    """
    Export the unused policies report to a CSV file.

    :param report: List of dictionaries containing policy information
    :param filename: Name of the CSV file to create
    """
    with open(filename, "w", newline="") as csvfile:
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

    print(f"CSV report exported to {filename}")


def generate_pdf_report(report, filename="unused_policies_report.pdf"):
    """
    Generate a PDF report of the unused policies, with each firewall starting on a new page.

    :param report: List of dictionaries containing policy information
    :param filename: Name of the PDF file to create
    """
    doc = SimpleDocTemplate(
        filename,
        pagesize=landscape(letter),
        leftMargin=0.3 * inch,
        rightMargin=0.3 * inch,
        topMargin=0.3 * inch,
        bottomMargin=0.3 * inch,
    )
    elements = []

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]

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
        data = [
            [
                "Policy",
                "Last Seen Unused",
                "First Seen Unused",
                "Days Since Last Import",
                "Total Days Unused",
            ]
        ]
        for policy in policies:
            data.append(
                [
                    policy["Policy"],
                    policy["Last Seen Unused"],
                    policy["First Seen Unused"],
                    str(policy["Days Since Last Import"]),
                    str(policy["Total Days Unused"]),
                ]
            )

        # Create the table
        table = Table(
            data, colWidths=[6.6 * inch, 0.9 * inch, 0.9 * inch, 0.7 * inch, 0.7 * inch]
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("TOPPADDING", (0, 1), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("WORDWRAP", (0, 0), (-1, -1), True),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )

        elements.append(table)
        elements.append(PageBreak())

    doc.build(elements)
