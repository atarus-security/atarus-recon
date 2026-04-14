import os
from weasyprint import HTML
from atarus_recon.reports import html as html_report
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator


def generate(result: ScanResult, output_dir: str) -> str:
    """Generate a PDF report from scan results"""

    os.makedirs(output_dir, exist_ok=True)

    html_path = html_report.generate(result, output_dir)

    with open(html_path, "r") as f:
        html_content = f.read()

    pdf_css = """
    <style>
      body { background: #060606 !important; }
      .tabs { display: none !important; }
      .tab-content { display: block !important; margin-bottom: 40px; }
      .host-body { max-height: none !important; padding: 0 20px 16px !important; }
      .host-body.collapsed { max-height: none !important; padding: 0 20px 16px !important; }
      .toggle { display: none !important; }
      .host-header { cursor: default !important; }
      .screenshot-container img { max-height: 300px; object-fit: contain; }

      @page {
        size: A4;
        margin: 20mm 15mm;
        @bottom-center {
          content: "Atarus Offensive Security | Confidential";
          font-size: 9px;
          color: #555;
        }
        @bottom-right {
          content: "Page " counter(page) " of " counter(pages);
          font-size: 9px;
          color: #555;
        }
      }

      @page :first {
        margin-top: 15mm;
      }

      .tab-content::before {
        display: block;
        font-size: 18px;
        font-weight: 600;
        color: #D4263E;
        margin-bottom: 16px;
        padding-bottom: 8px;
        border-bottom: 1px solid #1a1a1a;
      }
      #tab-overview::before { content: "Overview"; }
      #tab-hosts::before { content: "Hosts"; }
      #tab-vulns::before { content: "Vulnerabilities"; }
      #tab-infra::before { content: "Infrastructure"; }

      .host-section { page-break-inside: avoid; }
      .finding-card { page-break-inside: avoid; }
      .infra-card { page-break-inside: avoid; }
    </style>
    """

    html_content = html_content.replace("</head>", pdf_css + "</head>")

    safe_target = ScopeValidator.sanitize_filename(result.target)
    pdf_path = os.path.join(output_dir, f"atarus-recon-{safe_target}.pdf")

    HTML(string=html_content).write_pdf(pdf_path)

    return pdf_path
