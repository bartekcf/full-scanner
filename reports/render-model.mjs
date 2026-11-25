import pdfMake from "pdfmake/build/pdfmake.js"
import pdfFonts from "pdfmake/build/vfs_fonts.js"

const THEME = {
  background: "#090C18",
  surface: "#111827",
  inset: "#0B1221",
  border: "#28354D",
  text: "#F8FAFC",
  muted: "#ADBBD0",
  purple: "#7C3AED",
  lavender: "#C4B5FD",
  cyan: "#22D3EE",
}
const PRIORITY_COLORS = {
  urgent: "#FB7185",
  review: "#FBBF24",
  improve: "#38BDF8",
  info: "#A78BFA",
}
const RISK_LABELS = {
  critical: "krytyczny",
  high: "wysoki",
  medium: "średni",
  low: "niski",
  info: "informacyjny",
  informational: "informacyjny",
}
const CONFIDENCE_LABELS = {
  low: "niska",
  medium: "średnia",
  high: "wysoka",
  confirmed: "potwierdzona przez regułę (nie podatność)",
  false_positive: "oznaczona jako fałszywy alarm przez źródło",
}
const text = value =>
  typeof value === "string"
    ? value.replace(/\S{45,}/gu, part => part.match(/.{1,40}/gu).join("\u200b"))
    : ""
const unique = values => [...new Set(values.filter(Boolean))]
const paragraph = (value, style = "body") => ({
  text: text(value),
  style,
  margin: [0, 0, 0, 7],
})
const sectionLabel = value => ({
  text: text(value.toLocaleUpperCase("pl-PL")),
  style: "sectionLabel",
  headlineLevel: 1,
})

function panel(content, borderColor = THEME.border, minHeight) {
  return {
    table: {
      widths: ["100%"],
      heights: minHeight,
      body: [[{ stack: content, fillColor: THEME.surface, margin: [14, 13, 14, 13] }]],
    },
    layout: {
      hLineWidth: () => 0.6,
      vLineWidth: () => 0.6,
      hLineColor: () => borderColor,
      vLineColor: () => borderColor,
      paddingLeft: () => 0,
      paddingRight: () => 0,
      paddingTop: () => 0,
      paddingBottom: () => 0,
    },
    margin: [0, 0, 0, 12],
  }
}

function dataTable(headers, rows, widths) {
  return {
    table: {
      headerRows: 1,
      keepWithHeaderRows: 1,
      dontBreakRows: true,
      widths,
      body: [
        headers.map(value => ({
          text: text(value),
          bold: true,
          fillColor: THEME.inset,
          color: THEME.cyan,
        })),
        ...rows.map(row =>
          row.map(value => ({
            text: text(String(value ?? "")),
            fillColor: THEME.surface,
            color: THEME.text,
          }))
        ),
      ],
    },
    layout: {
      hLineWidth: () => 0.5,
      vLineWidth: () => 0,
      hLineColor: () => THEME.border,
      paddingLeft: () => 7,
      paddingRight: () => 7,
      paddingTop: () => 6,
      paddingBottom: () => 6,
    },
    fontSize: 8.5,
    margin: [0, 4, 0, 12],
  }
}

function priorityDonut(counts) {
  const radius = 51
  const circumference = 2 * Math.PI * radius
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0)
  let offset = 0
  const segments = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([priority, count]) => {
      const length = (count / total) * circumference
      const dash =
        count === total
          ? ""
          : `stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}"`
      offset += length
      return `<circle cx="68" cy="68" r="${radius}" fill="none" stroke="${PRIORITY_COLORS[priority] || THEME.muted}" stroke-width="15" ${dash} transform="rotate(-90 68 68)"/>`
    })
  return {
    svg: `<svg xmlns="http://www.w3.org/2000/svg" width="136" height="136" viewBox="0 0 136 136"><circle cx="68" cy="68" r="${radius}" fill="none" stroke="${THEME.border}" stroke-width="15"/>${segments.join("")}<text x="68" y="68" text-anchor="middle" fill="${THEME.text}" font-family="Roboto" font-size="29" font-weight="bold">${total}</text><text x="68" y="85" text-anchor="middle" fill="${THEME.muted}" font-family="Roboto" font-size="10">obszary</text></svg>`,
    width: 116,
    alignment: "center",
    margin: [0, 7, 0, 7],
  }
}

function overviewDashboard(model) {
  const priorities = model.policy.priorities
  const priorityCounts = Object.fromEntries(Object.keys(priorities).map(key => [key, 0]))
  for (const finding of model.findings) {
    if (Object.hasOwn(priorityCounts, finding.priority)) priorityCounts[finding.priority] += 1
  }
  const priorityContent = [
    { text: "Priorytet weryfikacji", style: "cardTitle" },
    { text: "Liczba obszarów głównych ustaleń", style: "small" },
    priorityDonut(priorityCounts),
    ...Object.entries(priorities)
      .sort((a, b) => a[1].rank - b[1].rank)
      .map(([key, value]) => ({
        columns: [
          {
            canvas: [{
              type: "ellipse",
              x: 3,
              y: 5,
              r1: 2.5,
              r2: 2.5,
              color: PRIORITY_COLORS[key] || THEME.muted,
            }],
            width: 12,
          },
          { text: value.label, width: "*", color: THEME.muted },
          { text: String(priorityCounts[key]), bold: true, alignment: "right", width: 35 },
        ],
        fontSize: 8.5,
        margin: [0, 0, 0, 4],
      })),
  ]

  const areas = model.findings
    .map(group => ({
      title: model.policy.groups[group.group]?.title || group.title,
      count: group.variants.length,
      priority: group.priority,
    }))
    .sort((a, b) => b.count - a.count || a.title.localeCompare(b.title, "pl"))
  const maximum = Math.max(1, ...areas.map(area => area.count))
  const areaContent = [
    { text: "Obszary ustaleń", style: "cardTitle" },
    { text: "Liczba odrębnych wariantów", style: "small", margin: [0, 0, 0, 14] },
  ]
  if (!areas.length) {
    areaContent.push(
      { text: "Brak ustaleń do pogrupowania", fontSize: 15, color: THEME.cyan, margin: [0, 28, 0, 12] },
      { text: model.summary.text, style: "bodyMuted" }
    )
  } else {
    for (const area of areas) {
      areaContent.push(
        {
          columns: [
            { text: area.title, width: "84%" },
            { text: String(area.count), width: "16%", alignment: "right", bold: true },
          ],
          fontSize: 8.5,
          margin: [0, 0, 0, 5],
        },
        {
          canvas: [
            { type: "rect", x: 0, y: 0, w: 208, h: 5, r: 2.5, color: THEME.border },
            {
              type: "rect",
              x: 0,
              y: 0,
              w: (area.count / maximum) * 208,
              h: 5,
              r: 2.5,
              color: PRIORITY_COLORS[area.priority] || THEME.cyan,
            },
          ],
          margin: [0, 0, 0, 12],
        }
      )
    }
  }

  return {
    columns: [
      { width: "50%", stack: [panel(priorityContent, THEME.border, 250)] },
      { width: "50%", stack: [panel(areaContent, THEME.border, 250)] },
    ],
    columnGap: 12,
    unbreakable: true,
  }
}

function evidence(variant, labels) {
  const instances = variant.instances || []
  const selected = instances.slice(0, 3)
  const nodes = []
  for (const instance of selected) {
    const details = [
      instance.url && `${labels.location}: ${instance.url}`,
      instance.method && `Metoda: ${instance.method}`,
      instance.evidence,
      [instance.alert_ref || instance.plugin_id, instance.original_name]
        .filter(Boolean)
        .join(" · "),
      instance.basis,
    ].filter(Boolean)
    nodes.push(paragraph(details.join("\n"), "small"))
  }
  if (instances.length > selected.length) {
    nodes.push(
      paragraph(
        `Pokazano ${selected.length} reprezentatywne przykłady z ${instances.length} zapisanych wystąpień tej obserwacji.`,
        "small"
      )
    )
  }
  if (!nodes.length) {
    nodes.push(paragraph("Dostępne dane nie zawierają bezpiecznego przykładu technicznego.", "small"))
  }
  return nodes
}

function findingSections(model, sectionNumber) {
  if (!model.findings.length) return []
  const copy = model.copy.report
  const priorities = model.policy.priorities
  const labels = copy.finding_labels
  const nodes = [
    sectionLabel(`${String(sectionNumber).padStart(2, "0")} / ${copy.sections.details}`),
    { text: copy.sections.details, style: "pageTitle", headlineLevel: 2 },
  ]

  for (const [index, group] of model.findings.entries()) {
    const priority = priorities[group.priority]
    const color = PRIORITY_COLORS[group.priority] || THEME.muted
    nodes.push({
      text: `${group.number} / ${group.title}`,
      style: "pageTitle",
      headlineLevel: 2,
      id: `finding-${group.number}`,
      pageBreak: index === 0 ? undefined : "before",
    })
    nodes.push({
      text: priority?.label || group.priority,
      color,
      bold: true,
      fontSize: 9,
      margin: [0, 0, 0, 10],
    })

    for (const variant of group.variants) {
      const risks = unique((variant.scanner_risks || []).map(value => RISK_LABELS[value] || value))
      const confidences = unique(
        (variant.scanner_confidences || []).map(value => CONFIDENCE_LABELS[value] || value)
      )
      nodes.push(
        panel([
          { text: variant.title, style: "cardTitle", color: THEME.cyan },
          paragraph(variant.observation),
          paragraph(
            `${labels.scanner_severity}: ${risks.join(", ") || "brak danych"}  ·  ${labels.confidence}: ${confidences.join(", ") || "brak danych"}  ·  ${labels.evidence}: ${(variant.instances || []).length}`,
            "small"
          ),
          ...evidence(variant, labels),
          ...(variant.review_justification
            ? [paragraph(`Jawna recenzja administratora: ${variant.review_justification}`, "small")]
            : []),
        ], color)
      )
    }

    for (const field of ["impact", "recommendation", "verification"]) {
      const values = unique(group.variants.map(variant => variant[field]))
      if (values.length) {
        nodes.push(
          paragraph(labels[field], "fieldLabel"),
          paragraph(values.join(" "))
        )
      }
    }
    const limitations = unique(group.variants.map(variant => variant.limitations))
    if (limitations.length) nodes.push(paragraph(limitations.join(" "), "small"))
    const references = unique(group.variants.flatMap(variant => variant.references || []))
    if (references.length) {
      nodes.push(paragraph(`Dokumentacja reguł: ${references.join(" · ")}`, "small"))
    }
  }

  return nodes
}

function technicalSection(model, sectionNumber) {
  const copy = model.copy.report
  if (!model.technical_observations.length) return []
  const rows = model.technical_observations.map(item => {
    const evidenceItems = unique(
      item.instances
        .map(instance => instance.evidence)
        .filter(value => /^(script:|link:|zasób:)/u.test(value || ""))
    ).slice(0, 3)
    const sources = unique(
      item.instances.map(instance =>
        `${instance.original_name || "obserwacja"} (ZAP ${instance.alert_ref || instance.plugin_id || "bez kodu"})`
      )
    )
    return [
      item.title,
      [
        item.observation,
        item.impact,
        item.priority === "info" ? "" : item.recommendation,
        evidenceItems.join("; "),
        sources.join("; "),
      ].filter(Boolean).join("\n"),
      String(item.instances.length),
    ]
  })
  const nodes = [
    sectionLabel(`${String(sectionNumber).padStart(2, "0")} / ${copy.sections.remaining}`),
    { text: copy.sections.remaining, style: "pageTitle", headlineLevel: 2 },
    dataTable(["Obserwacja", "Kontekst i interpretacja", "Wystąpienia"], rows, ["27%", "61%", "12%"]),
  ]
  if (model.technical_observations.some(item => item.rule_key === "timestamp")) {
    nodes.push(
      paragraph(
        "Publiczne daty i znaczniki czasu same w sobie nie oznaczają problemu bezpieczeństwa. Liczba ich wystąpień nie jest liczbą podatności.",
        "small"
      )
    )
  }
  return nodes
}

function cveSection(model, sectionNumber) {
  const copy = model.copy.report
  if (!model.cve_candidates.length) return []
  const nodes = [
    sectionLabel(`${String(sectionNumber).padStart(2, "0")} / Technologie i kandydaci CVE`),
    { text: "Technologie i kandydaci CVE", style: "pageTitle", headlineLevel: 2 },
    paragraph(copy.cve_note, "bodyMuted"),
  ]
  for (const candidate of model.cve_candidates) {
    const statuses = Object.entries(candidate.statuses || {})
      .map(([key, value]) => `${key}: ${value}`)
      .join("; ")
    nodes.push(
      panel([
        { text: `${candidate.product} / ${candidate.version}`, style: "cardTitle", color: THEME.cyan },
        paragraph(
          `Zapisane dopasowania: ${candidate.count}. ${statuses}. ${candidate.backports || ""}`,
          "bodyMuted"
        ),
        ...(candidate.sources?.length
          ? [paragraph(`Źródła: ${candidate.sources.join(", ")}`, "small")]
          : []),
        ...(candidate.identifiers?.length
          ? [
              paragraph(
                `Przykładowe identyfikatory: ${candidate.identifiers.slice(0, 5).join(", ")}${
                  candidate.identifiers.length > 5
                    ? `. Pokazano 5 z ${candidate.identifiers.length} identyfikatorów powiązanych z tą wersją; żaden nie został tutaj potwierdzony testem wykorzystania.`
                    : ". Nie potwierdzono możliwości wykorzystania."
                }`,
                "small"
              ),
            ]
          : []),
        ...(candidate.references?.length
          ? [paragraph(`Przykładowe źródła szczegółowe: ${candidate.references.slice(0, 2).join(" · ")}`, "small")]
          : []),
      ])
    )
  }
  return nodes
}

function actionAndScope(model, firstSectionNumber) {
  const copy = model.copy.report
  let sectionNumber = firstSectionNumber
  const serial = () => String(sectionNumber++).padStart(2, "0")
  const nodes = [
    sectionLabel(`${serial()} / ${copy.summary_headings[2]}`),
    { text: copy.summary_headings[2], style: "pageTitle", headlineLevel: 2 },
    panel([
      paragraph(model.summary.action, "bodyMuted"),
      paragraph(copy.review_notice, "small"),
    ]),
  ]
  if (model.summary.important_rows.length) {
    nodes.push(
      paragraph(copy.summary_headings[1], "fieldLabel"),
      ...model.summary.important_rows.map(row =>
        panel([
          {
            text: `${row.number} / ${row.title}`,
            style: "cardTitle",
            color: THEME.cyan,
            linkToDestination: `finding-${row.number}`,
          },
          paragraph(row.recommendation, "bodyMuted"),
        ])
      )
    )
  }
  nodes.push(
    sectionLabel(`${serial()} / ${copy.sections.coverage}`),
    { text: copy.sections.coverage, style: "pageTitle", headlineLevel: 2 }
  )
  if (model.coverage.checks.length) {
    nodes.push(
      dataTable(
        ["Kontrola", "Status", "Uwagi"],
        model.coverage.checks.map(row => [
          row.label,
          model.policy.coverage.statuses[row.status] || model.policy.coverage.statuses.unknown,
          row.note,
        ]),
        ["29%", "23%", "48%"]
      )
    )
  } else {
    nodes.push(
      paragraph(
        "Brak zapisanego wykazu kontroli. Zakres można określić wyłącznie na podstawie obserwacji zawartych w raporcie."
      )
    )
  }
  if (model.coverage.errors.length) {
    nodes.push(...unique(model.coverage.errors.map(error => error.message)).map(error => paragraph(error)))
  }
  nodes.push(
    paragraph(
      `Zapis źródłowy zawiera ${model.summary.original_alert_count} alertów; po usunięciu powtórzeń: ${model.summary.instance_count} instancji. W raporcie: ${model.summary.group_count} obszarów ustaleń oraz ${model.summary.technical_group_count} grup informacji technicznych. Te liczby nie oznaczają liczby podatności.`,
      "small"
    ),
    sectionLabel(`${serial()} / ${copy.sections.limits}`),
    { text: copy.sections.limits, style: "pageTitle", headlineLevel: 2 },
    paragraph(copy.limitations, "bodyMuted")
  )
  const brand = model.copy.brand
  const contact = [
    sectionLabel(`${serial()} / ${copy.sections.contact}`),
    { text: copy.sections.contact, style: "pageTitle", headlineLevel: 2 },
  ]
  const channels = [brand.email, brand.phone].filter(Boolean).join(" · ")
  if (channels) contact.push(paragraph(`${copy.contact_text}\n${channels}`))
  if (brand.website) {
    contact.push({
      text: [
        `${copy.website_label} `,
        {
          text: text(brand.website.replace(/^https?:\/\/|\/$/gu, "")),
          link: brand.website,
          color: THEME.cyan,
          decoration: "underline",
        },
        ".",
      ],
      style: "bodyMuted",
      margin: [0, 0, 0, 7],
    })
  }
  if (brand.legal_name) {
    const operator = [
      brand.address ? `${brand.legal_name}, ${brand.address}` : brand.legal_name,
      brand.nip && `NIP ${brand.nip}`,
      brand.krs && `KRS ${brand.krs}`,
    ].filter(Boolean).join(" · ")
    contact.push(paragraph(`${copy.operator_label} ${operator}`, "small"))
  }
  contact.push(
    paragraph(
      `Numer raportu: ${model.metadata.report_id} · Generator ${model.metadata.generator_version}\nData źródłowa: ${model.metadata.scanned_at || "brak danych"} · Strefa: ${model.metadata.timezone}`,
      "small"
    )
  )
  nodes.push({ stack: contact, unbreakable: true })
  return nodes
}
function briefCveSection(model) {
  const brief = model.brief_cves
  const items = Array.isArray(brief?.items) ? brief.items.slice(0, 3) : []
  if (!items.length) return []
  const nodes = [
    { ...sectionLabel("02 / NAJWAŻNIEJSZE CVE"), pageBreak: "before" },
    { text: "Najważniejsze CVE", style: "pageTitle", headlineLevel: 2 },
    ...(brief.note ? [paragraph(brief.note, "bodyMuted")] : []),
  ]
  for (const item of items) {
    const content = [
      { text: `${item.identifier} · ${item.product} ${item.version}`, style: "cardTitle", color: THEME.cyan },
      paragraph(
        `${item.match_status_label} — do weryfikacji · Pewność: ${item.confidence_label} · Poprawki dostawcy: ${item.backport_status_label}`,
        "small"
      ),
      paragraph(item.explanation),
      paragraph(`Zalecenie: ${item.recommendation}`, "bodyMuted"),
      ...(item.vendor_link
        ? [{
            text: [{ text: "Informacja producenta", link: item.vendor_link, color: THEME.cyan, decoration: "underline" }],
            fontSize: 8.5,
            margin: [0, 0, 0, 7],
          }]
        : []),
    ]
    nodes.push({ unbreakable: true, stack: [panel(content)] })
  }
  return nodes
}

function briefScopeAndContact(model, sectionNumber) {
  const brand = model.copy.brand
  const company = brand.legal_name || "Codefellow Sp. z o.o."
  const contact = [
    sectionLabel(`${String(sectionNumber).padStart(2, "0")} / ZAKRES I KONTAKT`),
    { text: "Zakres i kontakt", style: "pageTitle", headlineLevel: 2 },
    paragraph(
      "Raport przedstawia najważniejsze obserwacje z pasywnej analizy publicznie dostępnej strony. Ma charakter informacyjny i nie stanowi pełnego audytu bezpieczeństwa. Wskazane dopasowania CVE wymagają weryfikacji przez administratora serwisu.",
      "bodyMuted"
    ),
    paragraph(
      "W razie pytań dotyczących przedstawionych ustaleń prosimy o kontakt z Codefellow Sp. z o.o.",
      "bodyMuted"
    ),
    { text: company, style: "cardTitle", color: THEME.cyan },
    paragraph([brand.email, brand.phone].filter(Boolean).join(" · ")),
  ]
  if (brand.website) {
    contact.push({
      text: [{
        text: text(brand.website.replace(/^https?:\/\/|\/$/gu, "")),
        link: brand.website,
        color: THEME.cyan,
        decoration: "underline",
      }],
      style: "small",
      margin: [0, 0, 0, 7],
    })
  }
  const companyDetails = [
    brand.address,
    brand.nip && `NIP ${brand.nip}`,
    brand.krs && `KRS ${brand.krs}`,
  ].filter(Boolean).join(" · ")
  if (companyDetails) contact.push(paragraph(companyDetails, "small"))
  return [{ stack: contact, unbreakable: true }]
}


export function documentDefinition(model) {
  return createDocumentDefinition(model, false)
}

export function briefDocumentDefinition(model) {
  return createDocumentDefinition(model, true)
}

function createDocumentDefinition(model, brief) {
  const metadata = model.metadata
  const copy = model.copy.report
  const brand = brief ? { ...model.copy.brand, name: "Codefellow Scout" } : model.copy.brand
  const date = metadata.scanned_at
    ? new Intl.DateTimeFormat("pl-PL", {
        dateStyle: "long",
        timeZone: metadata.timezone,
      }).format(new Date(metadata.scanned_at))
    : null
  const nodes = [
    { text: brand.name, style: "brand" },
    ...(date ? [paragraph(`${copy.labels.date}: ${date}`, "small")] : []),
    { text: copy.title, style: "title" },
    { text: metadata.domain, style: "domain" },
  ]
  nodes.push(sectionLabel("01 / SYGNAŁY W LICZBACH"), overviewDashboard(model))

  if (model.coverage.status !== "no_usable_data") {
    nodes.push(
      paragraph(
        date
          ? copy.intro.replace("{date}", date).replace("{target}", metadata.domain)
          : "Przygotowano analizę zapisanych danych publicznie dostępnej strony. W źródle nie podano wiarygodnej daty wykonania skanu."
      )
    )
  }
  nodes.push(
    { text: copy.summary_headings[0], style: "pageTitle", headlineLevel: 2 },
    panel([paragraph(model.summary.text, "bodyMuted")])
  )
  if (model.coverage.status === "partial") {
    nodes.push({
      text: copy.coverage_notice.replace(
        "{checks}",
        unique(model.coverage.incomplete).join(", ") || "niepełny zapis przebiegu skanu"
      ),
      color: THEME.cyan,
      bold: true,
      margin: [0, 9, 0, 10],
    })
  }
  if (brief) {
    const hasCves = Array.isArray(model.brief_cves?.items) && model.brief_cves.items.length > 0
    const company = model.copy.brand.legal_name || "Codefellow Sp. z o.o."
    nodes.push(paragraph(
      `Raport przygotowany przez ${company} przy użyciu narzędzia ${brand.name}`,
      "small"
    ))
    if (hasCves) nodes.push(...briefCveSection(model))
    nodes.push(...briefScopeAndContact(model, hasCves ? 3 : 2))
  } else {
    if (model.summary.important_rows.length) {
      nodes.push({
        unbreakable: true,
        stack: [
          { text: copy.summary_headings[1], style: "pageTitle", headlineLevel: 2 },
          dataTable(
            ["Obszar", "Zaobserwowany element", "Zalecane działanie"],
            model.summary.important_rows.map(row => [
              row.area,
              row.title,
              `${row.recommendation} (${row.number})`,
            ]),
            ["25%", "35%", "40%"]
          ),
        ],
      })
      if (model.findings.length > model.summary.important_rows.length) {
        nodes.push(
          paragraph(
            `Pozostałe ustalenia znajdują się w dalszej części tego samego raportu: ${model.findings.slice(model.summary.important_rows.length).map(group => group.number).join(", ")}.`,
            "small"
          )
        )
      }
    }
    nodes.push(paragraph(model.summary.action, "bodyMuted"), paragraph(copy.review_notice, "small"))
    let nextSection = 2
    if (model.findings.length) nodes.push(...findingSections(model, nextSection++))
    if (model.technical_observations.length) {
      nodes.push(...technicalSection(model, nextSection++))
    }
    if (model.cve_candidates.length) nodes.push(...cveSection(model, nextSection++))
    nodes.push(...actionAndScope(model, nextSection))
  }

  return {
    pageSize: "A4",
    pageMargins: [44, 78, 44, 60],
    info: {
      title: `${copy.title} — ${metadata.domain}`,
      author: brief ? "Codefellow Sp. z o.o." : brand.name,
      subject: "Analiza zapisanych obserwacji pasywnych",
    },
    defaultStyle: {
      font: "Roboto",
      color: THEME.text,
      fontSize: 9.5,
      lineHeight: 1.22,
    },
    background: (_page, size) => ({
      canvas: [
        { type: "rect", x: 0, y: 0, w: size.width, h: size.height, color: THEME.background },
        {
          type: "rect",
          x: 0,
          y: 0,
          w: size.width,
          h: 4,
          linearGradient: [THEME.purple, THEME.cyan],
        },
        {
          type: "ellipse",
          x: size.width - 60,
          y: 30,
          r1: 210,
          r2: 180,
          color: THEME.purple,
          fillOpacity: 0.045,
        },
      ],
    }),
    header: () => ({
      columns: [
        {
          width: 28,
          canvas: [
            {
              type: "polyline",
              points: [
                { x: 11, y: 0 },
                { x: 22, y: 5 },
                { x: 20, y: 16 },
                { x: 11, y: 24 },
                { x: 2, y: 16 },
                { x: 0, y: 5 },
              ],
              closePath: true,
              lineColor: THEME.lavender,
              lineWidth: 1.7,
            },
            {
              type: "polyline",
              points: [
                { x: 6, y: 11 },
                { x: 10, y: 15 },
                { x: 16, y: 8 },
              ],
              lineColor: THEME.cyan,
              lineWidth: 1.7,
            },
          ],
        },
        { text: brand.name, bold: true, fontSize: 16, margin: [6, 2, 0, 0] },
        { text: metadata.domain, fontSize: 7, color: THEME.muted, alignment: "right", margin: [0, 8, 0, 0] },
      ],
      margin: [44, 29, 44, 0],
    }),
    footer: (currentPage, pageCount) => ({
      stack: [
        {
          canvas: [{
            type: "line",
            x1: 0,
            y1: 0,
            x2: 507,
            y2: 0,
            lineWidth: 0.5,
            lineColor: THEME.border,
          }],
        },
        {
          columns: [
            { text: `${brand.name} / ${metadata.domain}`, color: THEME.muted, fontSize: 7 },
            {
              text: `${String(currentPage).padStart(2, "0")} / ${String(pageCount).padStart(2, "0")}`,
              alignment: "right",
              color: THEME.lavender,
              fontSize: 7,
            },
          ],
          margin: [0, 9, 0, 0],
        },
      ],
      margin: [44, 12, 44, 0],
    }),
    styles: {
      brand: { fontSize: 10, bold: true, color: THEME.cyan, characterSpacing: 1.1, margin: [0, 0, 0, 9] },
      title: { fontSize: 25, bold: true, lineHeight: 1.1, margin: [0, 0, 0, 8] },
      domain: { fontSize: 15, bold: true, color: THEME.cyan, margin: [0, 0, 0, 10] },
      pageTitle: { fontSize: 17, bold: true, color: THEME.text, margin: [0, 12, 0, 8] },
      sectionLabel: {
        fontSize: 8.5,
        bold: true,
        characterSpacing: 0.8,
        color: THEME.lavender,
        margin: [0, 14, 0, 10],
      },
      cardTitle: { fontSize: 11, bold: true, margin: [0, 0, 0, 5] },
      fieldLabel: { fontSize: 9, bold: true, color: THEME.cyan },
      body: { fontSize: 9.5, lineHeight: 1.28 },
      bodyMuted: { fontSize: 9.5, lineHeight: 1.28, color: THEME.muted },
      small: { fontSize: 8, lineHeight: 1.25, color: THEME.muted },
    },
    pageBreakBefore: (node, following) => node.headlineLevel === 2 && following.length === 0,
    content: nodes,
  }
}

async function renderDefinition(definition) {
  return new Promise((resolve, reject) => {
    const stream = pdfMake.createPdf(definition, undefined, undefined, pdfFonts).getStream()
    const chunks = []
    let size = 0
    stream.on("data", chunk => {
      size += chunk.length
      if (size > 32 * 1024 * 1024) {
        stream.destroy(new Error("PDF exceeds size limit"))
        return
      }
      chunks.push(Buffer.from(chunk))
    })
    stream.once("error", reject)
    stream.once("end", () => resolve(Buffer.concat(chunks)))
    stream.end()
  })
}

export async function renderModel(model) {
  return renderDefinition(documentDefinition(model))
}

export async function renderBriefModel(model) {
  return renderDefinition(briefDocumentDefinition(model))
}
