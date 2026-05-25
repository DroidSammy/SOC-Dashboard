const fs = require("fs");
const path = require("path");

const OUT = path.join(process.cwd(), "B-Tree_2-3_Intro_Insertion_Deletion.pptx");

const SLIDE_W = 13.333;
const SLIDE_H = 7.5;
const EMU = 914400;

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function emu(n) {
  return Math.round(n * EMU);
}

function xmlHeader() {
  return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
}

function color(hex) {
  return hex.replace("#", "").toUpperCase();
}

function rels(relsList) {
  return xmlHeader() +
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    relsList.map((r) => `<Relationship Id="${r.id}" Type="${r.type}" Target="${r.target}"/>`).join("") +
    "</Relationships>";
}

function rect(id, x, y, w, h, text, opts = {}) {
  const fill = color(opts.fill || "#FFFFFF");
  const line = color(opts.line || "#233044");
  const font = color(opts.font || "#1E293B");
  const size = opts.size || 18;
  const radius = opts.round ? ' prst="roundRect"' : ' prst="rect"';
  const bold = opts.bold ? "<a:b/>" : "";
  const align = opts.align || "ctr";
  const valign = opts.valign || "mid";
  return `
  <p:sp>
    <p:nvSpPr><p:cNvPr id="${id}" name="Shape ${id}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
    <p:spPr>
      <a:xfrm><a:off x="${emu(x)}" y="${emu(y)}"/><a:ext cx="${emu(w)}" cy="${emu(h)}"/></a:xfrm>
      <a:prstGeom${radius}><a:avLst/></a:prstGeom>
      <a:solidFill><a:srgbClr val="${fill}"/></a:solidFill>
      <a:ln w="${opts.lineWidth || 12700}"><a:solidFill><a:srgbClr val="${line}"/></a:solidFill></a:ln>
    </p:spPr>
    <p:txBody>
      <a:bodyPr anchor="${valign}" wrap="square"><a:spAutoFit/></a:bodyPr><a:lstStyle/>
      ${paras(text, size, font, bold, align)}
    </p:txBody>
  </p:sp>`;
}

function textbox(id, x, y, w, h, text, opts = {}) {
  const font = color(opts.font || "#1E293B");
  const size = opts.size || 18;
  const bold = opts.bold ? "<a:b/>" : "";
  const align = opts.align || "l";
  return `
  <p:sp>
    <p:nvSpPr><p:cNvPr id="${id}" name="Text ${id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
    <p:spPr>
      <a:xfrm><a:off x="${emu(x)}" y="${emu(y)}"/><a:ext cx="${emu(w)}" cy="${emu(h)}"/></a:xfrm>
      <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
      <a:noFill/><a:ln><a:noFill/></a:ln>
    </p:spPr>
    <p:txBody>
      <a:bodyPr wrap="square"><a:spAutoFit/></a:bodyPr><a:lstStyle/>
      ${paras(text, size, font, bold, align)}
    </p:txBody>
  </p:sp>`;
}

function paras(text, size, font, bold, align) {
  return String(text).split("\n").map((line) => {
    const bullet = line.trim().startsWith("•");
    const clean = bullet ? line.trim().replace(/^•\s*/, "") : line;
    const mar = bullet ? ' marL="342900" indent="-171450"' : "";
    return `<a:p><a:pPr algn="${align}"${mar}>${bullet ? "<a:buChar char=\"•\"/>" : ""}</a:pPr><a:r><a:rPr lang="en-US" sz="${size * 100}">${bold}<a:solidFill><a:srgbClr val="${font}"/></a:solidFill></a:rPr><a:t>${esc(clean)}</a:t></a:r></a:p>`;
  }).join("");
}

function line(id, x1, y1, x2, y2, opts = {}) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const flipH = dx < 0 ? ' flipH="1"' : "";
  const flipV = dy < 0 ? ' flipV="1"' : "";
  return `
  <p:cxnSp>
    <p:nvCxnSpPr><p:cNvPr id="${id}" name="Line ${id}"/><p:cNvCxnSpPr/><p:nvPr/></p:nvCxnSpPr>
    <p:spPr>
      <a:xfrm${flipH}${flipV}><a:off x="${emu(Math.min(x1, x2))}" y="${emu(Math.min(y1, y2))}"/><a:ext cx="${emu(Math.abs(dx) || 0.01)}" cy="${emu(Math.abs(dy) || 0.01)}"/></a:xfrm>
      <a:prstGeom prst="line"><a:avLst/></a:prstGeom>
      <a:ln w="${opts.width || 19050}"><a:solidFill><a:srgbClr val="${color(opts.color || "#64748B")}"/></a:solidFill></a:ln>
    </p:spPr>
  </p:cxnSp>`;
}

function node(id, x, y, keys, opts = {}) {
  const keyText = Array.isArray(keys) ? keys.join(" | ") : keys;
  const w = opts.w || (Array.isArray(keys) && keys.length > 1 ? 1.35 : 0.82);
  return rect(id, x, y, w, 0.55, keyText, {
    fill: opts.fill || "#E0F2FE",
    line: opts.line || "#0369A1",
    font: opts.font || "#0F172A",
    size: opts.size || 18,
    bold: true,
    round: true
  });
}

function slideXml(shapes) {
  return xmlHeader() + `<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree>
  <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
  <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
  ${rect(2, 0, 0, SLIDE_W, SLIDE_H, "", { fill: "#F8FAFC", line: "#F8FAFC" })}
  ${shapes.join("\n")}
</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>`;
}

function title(id, text, subtitle) {
  return [
    textbox(id, 0.65, 0.35, 9.2, 0.65, text, { size: 30, bold: true, font: "#0F172A" }),
    subtitle ? textbox(id + 1, 0.72, 1.02, 11.5, 0.35, subtitle, { size: 13, font: "#475569" }) : ""
  ];
}

const slides = [];

slides.push(slideXml([
  ...title(10, "B-Tree of Order 3: 2-3 Tree", "Introduction, insertion and deletion with simple examples"),
  textbox(20, 0.78, 1.55, 5.15, 1.25, "A 2-3 tree is a balanced search tree where every internal node has either 2 children or 3 children.", { size: 20, font: "#1E293B" }),
  rect(21, 0.78, 3.05, 4.35, 1.25, "Why teachers like this topic\n• Shows balanced tree logic clearly\n• Basis for B-trees used in databases and filesystems", { fill: "#EEF2FF", line: "#4F46E5", size: 16, align: "l" }),
  node(30, 8.15, 1.55, [30]),
  line(31, 8.55, 2.1, 6.75, 3.0),
  line(32, 8.55, 2.1, 10.65, 3.0),
  node(33, 6.2, 3.0, [10, 20], { fill: "#DCFCE7", line: "#15803D" }),
  node(34, 10.2, 3.0, [40, 50], { fill: "#DCFCE7", line: "#15803D" }),
  textbox(35, 6.0, 4.05, 5.9, 0.75, "All leaves stay at the same level, so search stays efficient.", { size: 18, font: "#334155", align: "ctr" })
]));

slides.push(slideXml([
  ...title(10, "1. Introduction: Rules of a 2-3 Tree", "Each node stores 1 or 2 keys; the keys decide how many child pointers it owns."),
  rect(20, 0.75, 1.55, 5.75, 4.7, "Main properties\n• 2-node: 1 key and 2 children\n• 3-node: 2 keys and 3 children\n• Keys inside a node are sorted\n• Left values < first key\n• Middle values are between keys\n• Right values > second key\n• All leaves are at the same depth", { fill: "#FFFFFF", line: "#CBD5E1", size: 18, align: "l" }),
  rect(21, 7.05, 1.55, 2.1, 0.75, "2-node", { fill: "#DBEAFE", line: "#2563EB", bold: true }),
  node(22, 7.65, 2.55, [25]),
  line(23, 8.05, 3.1, 7.1, 4.0),
  line(24, 8.05, 3.1, 9.0, 4.0),
  rect(25, 6.65, 4.0, 1.15, 0.45, "< 25", { fill: "#F1F5F9", line: "#94A3B8", size: 14 }),
  rect(26, 8.55, 4.0, 1.15, 0.45, "> 25", { fill: "#F1F5F9", line: "#94A3B8", size: 14 }),
  rect(27, 10.05, 1.55, 2.1, 0.75, "3-node", { fill: "#DCFCE7", line: "#16A34A", bold: true }),
  node(28, 10.35, 2.55, [25, 60], { fill: "#DCFCE7", line: "#16A34A" }),
  line(29, 10.95, 3.1, 10.05, 4.0),
  line(30, 10.95, 3.1, 11.0, 4.0),
  line(31, 10.95, 3.1, 11.9, 4.0),
  rect(32, 9.55, 4.0, 0.9, 0.45, "< 25", { fill: "#F1F5F9", line: "#94A3B8", size: 13 }),
  rect(33, 10.62, 4.0, 0.9, 0.45, "25-60", { fill: "#F1F5F9", line: "#94A3B8", size: 13 }),
  rect(34, 11.68, 4.0, 0.9, 0.45, "> 60", { fill: "#F1F5F9", line: "#94A3B8", size: 13 })
]));

slides.push(slideXml([
  ...title(10, "2. Search Example", "Search is like a binary search tree, but a 3-node gives three possible directions."),
  node(20, 5.95, 1.35, [40]),
  line(21, 6.35, 1.9, 3.75, 2.9),
  line(22, 6.35, 1.9, 8.95, 2.9),
  node(23, 3.1, 2.9, [15, 25], { fill: "#DCFCE7", line: "#15803D" }),
  node(24, 8.3, 2.9, [60, 80], { fill: "#DCFCE7", line: "#15803D" }),
  line(25, 3.75, 3.45, 2.2, 4.55),
  line(26, 3.75, 3.45, 3.75, 4.55),
  line(27, 3.75, 3.45, 5.3, 4.55),
  line(28, 8.95, 3.45, 7.4, 4.55),
  line(29, 8.95, 3.45, 8.95, 4.55),
  line(30, 8.95, 3.45, 10.5, 4.55),
  node(31, 1.8, 4.55, [5], { fill: "#F8FAFC", line: "#94A3B8", size: 15 }),
  node(32, 3.35, 4.55, [20], { fill: "#F8FAFC", line: "#94A3B8", size: 15 }),
  node(33, 4.9, 4.55, [30], { fill: "#F8FAFC", line: "#94A3B8", size: 15 }),
  node(34, 7.0, 4.55, [50], { fill: "#F8FAFC", line: "#94A3B8", size: 15 }),
  node(35, 8.55, 4.55, [70], { fill: "#F8FAFC", line: "#94A3B8", size: 15 }),
  node(36, 10.1, 4.55, [90], { fill: "#F8FAFC", line: "#94A3B8", size: 15 }),
  rect(40, 0.78, 5.95, 11.75, 0.75, "Find 70: compare with 40 -> go right; compare in [60 | 80] -> go middle; leaf [70] found.", { fill: "#FEF3C7", line: "#D97706", size: 18 })
]));

slides.push(slideXml([
  ...title(10, "3. Insertion: Core Idea", "Insert at a leaf. If a node gets 3 keys, split it and promote the middle key upward."),
  rect(20, 0.75, 1.4, 4.05, 4.85, "Insertion steps\n• Search for the leaf position\n• Add the new key in sorted order\n• If the node has 1 or 2 keys, stop\n• If it has 3 keys, split into two nodes\n• Promote the middle key to the parent\n• If parent overflows, repeat upward\n• If root overflows, create a new root", { fill: "#FFFFFF", line: "#CBD5E1", size: 17, align: "l" }),
  textbox(21, 5.2, 1.55, 2.2, 0.45, "Overflow at leaf", { size: 17, bold: true, font: "#334155", align: "ctr" }),
  rect(22, 5.05, 2.25, 2.55, 0.65, "10 | 20 | 30", { fill: "#FEE2E2", line: "#DC2626", bold: true, size: 18 }),
  textbox(23, 7.95, 2.35, 0.9, 0.35, "split", { size: 16, font: "#64748B", align: "ctr" }),
  line(24, 7.55, 2.58, 8.85, 2.58, { color: "#64748B" }),
  node(25, 9.3, 1.75, [20], { fill: "#DBEAFE", line: "#2563EB" }),
  line(26, 9.72, 2.3, 8.9, 3.3),
  line(27, 9.72, 2.3, 10.75, 3.3),
  node(28, 8.5, 3.3, [10], { fill: "#DCFCE7", line: "#16A34A" }),
  node(29, 10.35, 3.3, [30], { fill: "#DCFCE7", line: "#16A34A" }),
  rect(30, 5.25, 4.8, 6.95, 0.9, "Middle key moves up; smaller and larger keys become two separate children.", { fill: "#EFF6FF", line: "#60A5FA", size: 18 })
]));

slides.push(slideXml([
  ...title(10, "4. Insertion Worked Example", "Insert: 10, 20, 30, 40, 50"),
  textbox(20, 0.8, 1.35, 2.0, 0.35, "After 10, 20", { size: 15, bold: true, font: "#334155", align: "ctr" }),
  node(21, 1.15, 1.95, [10, 20], { fill: "#DCFCE7", line: "#15803D" }),
  textbox(22, 3.65, 1.35, 2.0, 0.35, "Insert 30", { size: 15, bold: true, font: "#334155", align: "ctr" }),
  node(23, 4.05, 1.95, [20], { fill: "#DBEAFE", line: "#2563EB" }),
  line(24, 4.45, 2.5, 3.65, 3.3),
  line(25, 4.45, 2.5, 5.45, 3.3),
  node(26, 3.25, 3.3, [10], { fill: "#DCFCE7", line: "#15803D" }),
  node(27, 5.05, 3.3, [30], { fill: "#DCFCE7", line: "#15803D" }),
  textbox(28, 6.75, 1.35, 2.0, 0.35, "Insert 40", { size: 15, bold: true, font: "#334155", align: "ctr" }),
  node(29, 7.15, 1.95, [20], { fill: "#DBEAFE", line: "#2563EB" }),
  line(30, 7.55, 2.5, 6.75, 3.3),
  line(31, 7.55, 2.5, 8.55, 3.3),
  node(32, 6.35, 3.3, [10], { fill: "#DCFCE7", line: "#15803D" }),
  node(33, 8.15, 3.3, [30, 40], { fill: "#DCFCE7", line: "#15803D" }),
  textbox(34, 9.9, 1.35, 2.0, 0.35, "Insert 50", { size: 15, bold: true, font: "#334155", align: "ctr" }),
  node(35, 10.2, 1.95, [20, 40], { fill: "#DBEAFE", line: "#2563EB" }),
  line(36, 10.85, 2.5, 9.65, 3.3),
  line(37, 10.85, 2.5, 10.85, 3.3),
  line(38, 10.85, 2.5, 12.05, 3.3),
  node(39, 9.25, 3.3, [10], { fill: "#DCFCE7", line: "#15803D" }),
  node(40, 10.45, 3.3, [30], { fill: "#DCFCE7", line: "#15803D" }),
  node(41, 11.65, 3.3, [50], { fill: "#DCFCE7", line: "#15803D" }),
  rect(42, 1.0, 5.6, 11.3, 0.65, "Key observation: splits move upward only when a node temporarily holds 3 keys.", { fill: "#F0FDF4", line: "#22C55E", size: 18 })
]));

slides.push(slideXml([
  ...title(10, "5. Deletion: Core Idea", "Delete from a leaf when possible. If a node becomes empty, repair by borrowing or merging."),
  rect(20, 0.75, 1.35, 5.65, 4.8, "Deletion steps\n• Search for the key\n• If key is in an internal node, swap with predecessor/successor in a leaf\n• Delete the key from the leaf\n• If leaf still has 1 key, stop\n• If leaf becomes empty, first try borrowing from a sibling\n• If borrowing is not possible, merge with sibling and pull a parent key down", { fill: "#FFFFFF", line: "#CBD5E1", size: 17, align: "l" }),
  rect(21, 7.05, 1.45, 2.05, 0.6, "Borrow", { fill: "#DBEAFE", line: "#2563EB", bold: true }),
  node(22, 7.5, 2.35, [30]),
  line(23, 7.9, 2.9, 7.1, 3.7),
  line(24, 7.9, 2.9, 8.75, 3.7),
  rect(25, 6.75, 3.7, 0.8, 0.5, "empty", { fill: "#FEE2E2", line: "#DC2626", size: 12 }),
  node(26, 8.35, 3.7, [40, 50], { fill: "#DCFCE7", line: "#16A34A", size: 14 }),
  rect(27, 9.75, 1.45, 2.05, 0.6, "Merge", { fill: "#FEF3C7", line: "#D97706", bold: true }),
  node(28, 10.2, 2.35, [30]),
  line(29, 10.6, 2.9, 9.85, 3.7),
  line(30, 10.6, 2.9, 11.35, 3.7),
  rect(31, 9.5, 3.7, 0.8, 0.5, "empty", { fill: "#FEE2E2", line: "#DC2626", size: 12 }),
  node(32, 10.95, 3.7, [40], { fill: "#DCFCE7", line: "#16A34A", size: 14 }),
  rect(33, 7.1, 5.15, 4.65, 0.75, "Borrow if sibling has 2 keys; merge if sibling has only 1 key.", { fill: "#F8FAFC", line: "#94A3B8", size: 16 })
]));

slides.push(slideXml([
  ...title(10, "6. Deletion Worked Example + Recap", "Start with keys [10, 20, 30, 40, 50], then delete 10."),
  textbox(20, 0.95, 1.35, 2.8, 0.35, "Before deleting 10", { size: 16, bold: true, font: "#334155", align: "ctr" }),
  node(21, 1.65, 2.0, [20, 40], { fill: "#DBEAFE", line: "#2563EB" }),
  line(22, 2.3, 2.55, 1.1, 3.35),
  line(23, 2.3, 2.55, 2.3, 3.35),
  line(24, 2.3, 2.55, 3.5, 3.35),
  node(25, 0.7, 3.35, [10], { fill: "#DCFCE7", line: "#15803D" }),
  node(26, 1.9, 3.35, [30], { fill: "#DCFCE7", line: "#15803D" }),
  node(27, 3.1, 3.35, [50], { fill: "#DCFCE7", line: "#15803D" }),
  textbox(28, 5.1, 1.35, 2.8, 0.35, "After deleting 10", { size: 16, bold: true, font: "#334155", align: "ctr" }),
  rect(29, 5.9, 2.0, 1.35, 0.55, "20 | 40", { fill: "#FEE2E2", line: "#DC2626", bold: true, size: 16 }),
  line(30, 6.55, 2.55, 5.55, 3.35),
  line(31, 6.55, 2.55, 6.55, 3.35),
  line(32, 6.55, 2.55, 7.55, 3.35),
  rect(33, 5.15, 3.35, 0.8, 0.5, "empty", { fill: "#FEE2E2", line: "#DC2626", size: 12 }),
  node(34, 6.15, 3.35, [30], { fill: "#DCFCE7", line: "#15803D" }),
  node(35, 7.15, 3.35, [50], { fill: "#DCFCE7", line: "#15803D" }),
  textbox(36, 9.15, 1.35, 2.8, 0.35, "Repair by merge", { size: 16, bold: true, font: "#334155", align: "ctr" }),
  node(37, 9.85, 2.0, [40], { fill: "#DBEAFE", line: "#2563EB" }),
  line(38, 10.25, 2.55, 9.25, 3.35),
  line(39, 10.25, 2.55, 11.25, 3.35),
  node(40, 8.85, 3.35, [20, 30], { fill: "#DCFCE7", line: "#15803D" }),
  node(41, 10.85, 3.35, [50], { fill: "#DCFCE7", line: "#15803D" }),
  rect(42, 0.85, 5.35, 11.65, 0.95, "Recap: Search chooses the path. Insertion fixes overflow by split + promote. Deletion fixes underflow by borrow or merge. Height remains balanced.", { fill: "#EEF2FF", line: "#4F46E5", size: 18 })
]));

function contentTypes(count) {
  let overrides = "";
  for (let i = 1; i <= count; i++) {
    overrides += `<Override PartName="/ppt/slides/slide${i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>`;
  }
  return xmlHeader() + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
${overrides}</Types>`;
}

function presentation(count) {
  const ids = Array.from({ length: count }, (_, i) => `<p:sldId id="${256 + i}" r:id="rId${i + 1}"/>`).join("");
  return xmlHeader() + `<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId${count + 1}"/></p:sldMasterIdLst>
<p:sldIdLst>${ids}</p:sldIdLst>
<p:sldSz cx="${emu(SLIDE_W)}" cy="${emu(SLIDE_H)}" type="wide"/>
<p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>`;
}

function master() {
  return xmlHeader() + `<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld>
<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
<p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles>
</p:sldMaster>`;
}

function layout() {
  return xmlHeader() + `<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1">
<p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld>
<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>`;
}

function theme() {
  return xmlHeader() + `<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="BTreeTheme">
<a:themeElements><a:clrScheme name="BTree"><a:dk1><a:srgbClr val="0F172A"/></a:dk1><a:lt1><a:srgbClr val="F8FAFC"/></a:lt1><a:dk2><a:srgbClr val="334155"/></a:dk2><a:lt2><a:srgbClr val="E2E8F0"/></a:lt2><a:accent1><a:srgbClr val="2563EB"/></a:accent1><a:accent2><a:srgbClr val="16A34A"/></a:accent2><a:accent3><a:srgbClr val="D97706"/></a:accent3><a:accent4><a:srgbClr val="DC2626"/></a:accent4><a:accent5><a:srgbClr val="4F46E5"/></a:accent5><a:accent6><a:srgbClr val="0891B2"/></a:accent6><a:hlink><a:srgbClr val="2563EB"/></a:hlink><a:folHlink><a:srgbClr val="7C3AED"/></a:folHlink></a:clrScheme>
<a:fontScheme name="Aptos"><a:majorFont><a:latin typeface="Aptos Display"/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/></a:minorFont></a:fontScheme><a:fmtScheme name="BTreeFmt"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements>
</a:theme>`;
}

function core() {
  const now = new Date().toISOString();
  return xmlHeader() + `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>B-Tree 2-3: Introduction, Insertion, Deletion</dc:title><dc:creator>Codex</dc:creator><cp:lastModifiedBy>Codex</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${now}</dcterms:modified></cp:coreProperties>`;
}

function app() {
  return xmlHeader() + `<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Codex</Application><PresentationFormat>On-screen Show (16:9)</PresentationFormat><Slides>${slides.length}</Slides></Properties>`;
}

const files = {
  "[Content_Types].xml": contentTypes(slides.length),
  "_rels/.rels": rels([{ id: "rId1", type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", target: "ppt/presentation.xml" }, { id: "rId2", type: "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", target: "docProps/core.xml" }, { id: "rId3", type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties", target: "docProps/app.xml" }]),
  "docProps/core.xml": core(),
  "docProps/app.xml": app(),
  "ppt/presentation.xml": presentation(slides.length),
  "ppt/_rels/presentation.xml.rels": rels([
    ...slides.map((_, i) => ({ id: `rId${i + 1}`, type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide", target: `slides/slide${i + 1}.xml` })),
    { id: `rId${slides.length + 1}`, type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster", target: "slideMasters/slideMaster1.xml" },
    { id: `rId${slides.length + 2}`, type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme", target: "theme/theme1.xml" }
  ]),
  "ppt/slideMasters/slideMaster1.xml": master(),
  "ppt/slideMasters/_rels/slideMaster1.xml.rels": rels([{ id: "rId1", type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout", target: "../slideLayouts/slideLayout1.xml" }, { id: "rId2", type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme", target: "../theme/theme1.xml" }]),
  "ppt/slideLayouts/slideLayout1.xml": layout(),
  "ppt/slideLayouts/_rels/slideLayout1.xml.rels": rels([{ id: "rId1", type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster", target: "../slideMasters/slideMaster1.xml" }]),
  "ppt/theme/theme1.xml": theme()
};

slides.forEach((s, i) => {
  files[`ppt/slides/slide${i + 1}.xml`] = s;
  files[`ppt/slides/_rels/slide${i + 1}.xml.rels`] = rels([{ id: "rId1", type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout", target: "../slideLayouts/slideLayout1.xml" }]);
});

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function dosDateTime(date) {
  const year = Math.max(1980, date.getFullYear());
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
}

function makeZip(entries) {
  const now = dosDateTime(new Date());
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(entries)) {
    const data = Buffer.from(content, "utf8");
    const nameBuf = Buffer.from(name.replace(/\\/g, "/"), "utf8");
    const crc = crc32(data);
    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(0), u16(0), u16(now.time), u16(now.day), u32(crc),
      u32(data.length), u32(data.length), u16(nameBuf.length), u16(0), nameBuf, data
    ]);
    const central = Buffer.concat([
      u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(now.time), u16(now.day), u32(crc),
      u32(data.length), u32(data.length), u16(nameBuf.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), nameBuf
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const centralDir = Buffer.concat(centrals);
  const end = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(centrals.length), u16(centrals.length),
    u32(centralDir.length), u32(offset), u16(0)
  ]);
  return Buffer.concat([...locals, centralDir, end]);
}

fs.writeFileSync(OUT, makeZip(files));
console.log(`Created ${OUT}`);
