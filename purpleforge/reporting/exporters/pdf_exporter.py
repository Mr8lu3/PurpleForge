"""PDF report exporter using weasyprint or pandoc."""

import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from purpleforge.reporting.exporters.html_exporter import export_html
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


def _has_weasyprint() -> bool:
    """Check if weasyprint is available."""
    try:
        import weasyprint  # noqa: F401
        return True
    except ImportError:
        return False


def _has_pandoc() -> bool:
    """Check if pandoc is available."""
    return shutil.which("pandoc") is not None


def export_pdf_weasyprint(html_path: Path, output_path: Path) -> Optional[Path]:
    """
    Export PDF using weasyprint.

    Args:
        html_path: Path to HTML file
        output_path: Path for PDF output

    Returns:
        Path to created PDF or None if failed
    """
    try:
        from weasyprint import HTML, CSS

        # Custom CSS for better PDF output
        pdf_css = CSS(string='''
            @page {
                size: A4;
                margin: 2cm;
                @top-right {
                    content: "PurpleForge Report";
                    font-size: 10pt;
                    color: #666;
                }
                @bottom-center {
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 10pt;
                    color: #666;
                }
            }
            body {
                font-size: 11pt;
            }
            .header {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            pre {
                white-space: pre-wrap;
                word-wrap: break-word;
            }
        ''')

        html = HTML(filename=str(html_path))
        html.write_pdf(str(output_path), stylesheets=[pdf_css])

        logger.info(f"PDF exported via weasyprint: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"weasyprint PDF export failed: {e}")
        return None


def export_pdf_pandoc(markdown_path: Path, output_path: Path) -> Optional[Path]:
    """
    Export PDF using pandoc.

    Args:
        markdown_path: Path to Markdown file
        output_path: Path for PDF output

    Returns:
        Path to created PDF or None if failed
    """
    try:
        cmd = [
            "pandoc",
            str(markdown_path),
            "-o", str(output_path),
            "--pdf-engine=xelatex",
            "-V", "geometry:margin=2cm",
            "-V", "fontsize=11pt",
            "--toc",
            "--toc-depth=2",
            "-V", "colorlinks=true",
            "-V", "linkcolor=purple",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            logger.info(f"PDF exported via pandoc: {output_path}")
            return output_path
        else:
            logger.error(f"pandoc PDF export failed: {result.stderr}")
            return None

    except subprocess.TimeoutExpired:
        logger.error("pandoc PDF export timed out")
        return None
    except FileNotFoundError:
        logger.error("pandoc not found")
        return None
    except Exception as e:
        logger.error(f"pandoc PDF export error: {e}")
        return None


def export_pdf(
    report_data: Dict[str, Any],
    output_path: Path,
    markdown_path: Optional[Path] = None,
) -> Optional[Path]:
    """
    Export report as PDF.

    Tries weasyprint first (HTML to PDF), then falls back to pandoc (Markdown to PDF).

    Args:
        report_data: Report data dictionary
        output_path: Path for PDF output
        markdown_path: Optional path to existing Markdown report

    Returns:
        Path to created PDF or None if all methods failed
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Try weasyprint (HTML to PDF)
    if _has_weasyprint():
        logger.info("Using weasyprint for PDF generation")

        # Create temporary HTML
        temp_html = output_path.with_suffix(".html")
        export_html(report_data, temp_html)

        result = export_pdf_weasyprint(temp_html, output_path)

        # Clean up temp HTML
        if temp_html.exists():
            temp_html.unlink()

        if result:
            return result

    # Try pandoc (Markdown to PDF)
    if _has_pandoc() and markdown_path and markdown_path.exists():
        logger.info("Using pandoc for PDF generation")
        result = export_pdf_pandoc(markdown_path, output_path)
        if result:
            return result

    # All methods failed
    logger.warning(
        "PDF export unavailable. Install weasyprint (pip install weasyprint) "
        "or pandoc with xelatex for PDF generation."
    )
    return None


def check_pdf_support() -> Dict[str, bool]:
    """
    Check available PDF export methods.

    Returns:
        Dictionary with availability status
    """
    return {
        "weasyprint": _has_weasyprint(),
        "pandoc": _has_pandoc(),
    }
