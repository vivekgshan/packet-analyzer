import { toPng } from "html-to-image";
import { saveAs } from "file-saver";
import jsPDF from "jspdf";

export function exportCSV(packets) {
  const rows = [
    ["id","timestamp","protocol","srcIP","srcPort","destIP","destPort","length"],
    ...packets.map(p => [p.id, p.timestamp, p.protocol, p.srcIP, p.srcPort, p.destIP, p.destPort, p.length])
  ];
  const csv = rows.map(r => r.join(",")).join("\n");
  saveAs(new Blob([csv], { type: "text/csv;charset=utf-8;" }), "packets.csv");
}

export async function exportPDFFromNode(elementId, filename = "report.pdf") {
  const node = document.getElementById(elementId);
  if (!node) return alert("No element to export");

  const dataUrl = await toPng(node, { cacheBust: true });
  const pdf = new jsPDF("landscape");
  const imgProps = pdf.getImageProperties(dataUrl);
  const pdfWidth = pdf.internal.pageSize.getWidth();
  const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
  pdf.addImage(dataUrl, "PNG", 0, 10, pdfWidth, pdfHeight);
  pdf.save(filename);
}

export function shareJSON(packets) {
  const payload = { exportedAt: new Date().toISOString(), packets };
  navigator.clipboard?.writeText(JSON.stringify(payload, null, 2))
    .then(() => alert("Export JSON copied to clipboard"))
    .catch(() => alert("Could not copy to clipboard"));
}
