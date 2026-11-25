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

function dashboardData(model) {
  const priorities = model.policy.priorities
  const priorityCounts = Object.fromEntries(Object.keys(priorities).map(key => [key, 0]))
  for (const finding of model.findings) {
    if (Object.hasOwn(priorityCounts, finding.priority)) priorityCounts[finding.priority] += 1
  }
  const areas = model.findings
    .map(group => ({
      title: model.policy.groups[group.group]?.title || group.title,
      count: group.variants.length,
      priority: group.priority,
    }))
    .sort((a, b) => b.count - a.count || a.title.localeCompare(b.title, "pl"))
  const maximum = Math.max(1, ...areas.map(area => area.count))
  return { priorities, priorityCounts, areas, maximum }
}

function overviewDashboard(model) {
  const { priorities, priorityCounts, areas, maximum } = dashboardData(model)
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
function briefCveGroups(model) {
  const groups = new Map()
  const items = Array.isArray(model.brief_cves?.items) ? model.brief_cves.items.slice(0, 3) : []
  for (const item of items) {
    const product = item.product || item.technology_name || "Komponent"
    const version = item.version || item.detected_version || "nieustalona"
    const key = `${product.toLocaleLowerCase("pl-PL")}\u0000${version}`
    if (!groups.has(key)) groups.set(key, { product, version, items: [] })
    groups.get(key).items.push(item)
  }
  return [...groups.values()]
}

function briefCveSection(model) {
  const groups = briefCveGroups(model)
  if (!groups.length) return []
  const nodes = [
    { ...sectionLabel("02 / CO SPRAWDZIĆ W PIERWSZEJ KOLEJNOŚCI"), pageBreak: "before" },
    { text: "Co sprawdzić w pierwszej kolejności", style: "pageTitle", headlineLevel: 2 },
    ...(model.brief_cves.note ? [paragraph(model.brief_cves.note, "bodyMuted")] : []),
  ]
  for (const group of groups) {
    const content = [
      {
        text: `${group.product} · zaobserwowana wersja ${group.version}`,
        style: "cardTitle",
        color: THEME.cyan,
      },
      paragraph(`W skanie rozpoznano komponent ${group.product} w wersji ${group.version}.`),
    ]
    const explanations = new Map()
    for (const item of group.items) {
      const explanation = item.explanation?.trim()
      if (!explanation) continue
      const identifiers = explanations.get(explanation) || []
      identifiers.push(item.identifier)
      explanations.set(explanation, identifiers)
    }
    for (const [explanation, identifiers] of explanations) {
      content.push(paragraph(
        explanations.size > 1 ? `${identifiers.join(", ")}: ${explanation}` : explanation
      ))
    }
    const recommendations = new Map()
    for (const item of group.items) {
      const recommendation = item.recommendation?.trim()
      if (!recommendation) continue
      const identifiers = recommendations.get(recommendation) || []
      identifiers.push(item.identifier)
      recommendations.set(recommendation, identifiers)
    }
    for (const [recommendation, identifiers] of recommendations) {
      content.push(paragraph(
        `${recommendations.size > 1 ? `${identifiers.join(", ")}: ` : ""}Zalecenie: ${recommendation}`,
        "bodyMuted"
      ))
    }
    for (const item of group.items) {
      const status = briefMatchStatus(item)
      content.push(paragraph(
        `${item.identifier} · ${status} · pewność: ${item.confidence_label || "nieustalona"} · poprawki dostawcy: ${item.backport_status_label || "nieustalone"}`,
        "small"
      ))
      if (item.vendor_link) {
        content.push({
          text: [{
            text: `Informacja producenta — ${item.identifier}`,
            link: item.vendor_link,
            color: THEME.cyan,
            decoration: "underline",
          }],
          fontSize: 8.5,
          margin: [0, 0, 0, 7],
        })
      }
    }
    nodes.push({ unbreakable: true, stack: [panel(content)] })
  }
  return nodes
}

function briefObservations(model) {
  const important = Array.isArray(model.summary?.important_rows) ? model.summary.important_rows : []
  const importantRank = new Map(important.map((row, index) => [`${row.number}\u0000${row.title}`, index]))
  const candidates = []
  for (const [groupIndex, group] of (model.findings || []).entries()) {
    for (const [variantIndex, variant] of (group.variants || []).entries()) {
      const title = variant.title || group.title || "Ustalenie"
      if (
        group.group === "server_technology" &&
        /wersja|version/iu.test(title) &&
        /podatno|vulnerab|CVE/iu.test(title)
      ) continue
      const key = `${group.group}\u0000${title}\u0000${variant.recommendation || ""}`.toLocaleLowerCase("pl-PL")
      const highlighted = importantRank.get(`${group.number}\u0000${title}`)
      candidates.push({
        key,
        rank: highlighted ?? important.length + groupIndex * 10 + variantIndex,
        order: groupIndex * 100 + variantIndex,
        groupTitle: group.title || "Pozostałe ustalenia",
        title,
        priority: group.priority,
        observation: variant.observation || "",
        impact: variant.impact || "",
        recommendation: variant.recommendation || "",
      })
    }
  }
  candidates.sort((left, right) => left.rank - right.rank || left.order - right.order)
  const deduplicated = new Map()
  for (const item of candidates) {
    if (!deduplicated.has(item.key)) deduplicated.set(item.key, item)
  }
  const items = [...deduplicated.values()]
  return {
    items: items.slice(0, 4),
    omittedAreas: unique(items.slice(4).map(item => item.groupTitle)),
  }
}

function briefObservationSection(observations) {
  if (!observations.items.length) return []
  const nodes = [
    sectionLabel("03 / CO JESZCZE ZAOBSERWOWANO"),
    { text: "Co jeszcze zaobserwowano", style: "pageTitle", headlineLevel: 2 },
  ]
  for (const item of observations.items) {
    const content = [
      { text: `${item.groupTitle}: ${item.title}`, style: "cardTitle", color: THEME.cyan },
      ...(item.observation ? [paragraph(item.observation)] : []),
      ...(item.impact ? [paragraph(item.impact, "bodyMuted")] : []),
      ...(item.recommendation ? [paragraph(`Co sprawdzić: ${item.recommendation}`, "bodyMuted")] : []),
    ]
    nodes.push({ unbreakable: true, stack: [panel(content)] })
  }
  if (observations.omittedAreas.length) {
    nodes.push(paragraph(
      `Odnotowaliśmy również uwagi w obszarach: ${observations.omittedAreas.join(", ")}. Powyżej opisaliśmy kwestie, które zalecamy sprawdzić w pierwszej kolejności.`,
      "small"
    ))
  }
  return nodes
}

function briefScopeAndContact(model, sectionNumber, forcePageBreak = true) {
  const brand = model.copy.brand
  const contact = [
    sectionLabel(`${String(sectionNumber).padStart(2, "0")} / ZAKRES I KONTAKT`),
    { text: "Zakres i kontakt", style: "pageTitle", headlineLevel: 2 },
    paragraph(
      "Raport przygotowała firma Codefellow Sp. z o.o. przy użyciu narzędzia Codefellow Scout. Dokument przedstawia wybrane, najważniejsze obserwacje z pasywnej analizy publicznie dostępnej strony. Ma charakter informacyjny i nie stanowi pełnego audytu bezpieczeństwa. Wskazane dopasowania CVE wymagają weryfikacji przez administratora serwisu.",
      "bodyMuted"
    ),
    paragraph(
      "W razie pytań dotyczących przedstawionych ustaleń prosimy o kontakt.",
      "bodyMuted"
    ),
    { text: "Codefellow Sp. z o.o.", style: "cardTitle", color: THEME.cyan },
    paragraph([brand.email, brand.phone].filter(Boolean).join(" · ")),
  ]
  return [{ stack: contact, unbreakable: true, ...(forcePageBreak ? { pageBreak: "before" } : {}) }]
}

const PAPER_THEME = {
  white: "#FFFFFF",
  graphite: "#223746",
  steel: "#355F7D",
  paleBlue: "#EFF5F8",
  border: "#C8D6DE",
  muted: "#526A78",
  urgent: "#A94F32",
  improve: "#8299A7",
  info: "#C2CED5",
}
const PAPER_PRIORITY_COLORS = {
  urgent: PAPER_THEME.urgent,
  review: PAPER_THEME.steel,
  improve: PAPER_THEME.improve,
  info: PAPER_THEME.info,
}

function briefMatchStatus(item) {
  const label = item.match_status_label || "Dopasowanie do weryfikacji"
  return /potencjal/iu.test(label) && !/weryfikac/iu.test(label)
    ? `${label} — do weryfikacji`
    : label
}

function paperParagraph(value, style = "paperBody") {
  return { text: text(value), style, margin: [0, 0, 0, 6] }
}

function paperPanel(content, borderColor = PAPER_THEME.border, fillColor = PAPER_THEME.paleBlue, padding = [12, 10, 12, 10], marginBottom = 9) {
  return {
    table: {
      widths: ["100%"],
      body: [[{ stack: content, fillColor, margin: padding }]],
    },
    layout: {
      hLineWidth: () => 0.65,
      vLineWidth: () => 0.65,
      hLineColor: () => borderColor,
      vLineColor: () => borderColor,
      paddingLeft: () => 0,
      paddingRight: () => 0,
      paddingTop: () => 0,
      paddingBottom: () => 0,
    },
    margin: [0, 0, 0, marginBottom],
  }
}

function paperSectionLabel(value) {
  return {
    columns: [
      {
        canvas: [
          { type: "rect", x: 0, y: 0, w: 4, h: 14, color: PAPER_THEME.steel },
          {
            type: "rect",
            x: 8,
            y: 0,
            w: 12,
            h: 14,
            color: PAPER_THEME.paleBlue,
            lineColor: PAPER_THEME.border,
            lineWidth: 0.45,
          },
          { type: "line", x1: 10, y1: 7, x2: 18, y2: 7, lineColor: PAPER_THEME.steel, lineWidth: 0.8 },
        ],
        width: 24,
      },
      { text: text(value.toLocaleUpperCase("pl-PL")), style: "paperSection" },
    ],
    columnGap: 7,
    margin: [0, 9, 0, 7],
  }
}

function paperShield(color = PAPER_THEME.steel) {
  return {
    canvas: [
      {
        type: "polyline",
        points: [
          { x: 12, y: 0 },
          { x: 22, y: 4 },
          { x: 20, y: 16 },
          { x: 12, y: 25 },
          { x: 4, y: 16 },
          { x: 2, y: 4 },
        ],
        closePath: true,
        lineColor: color,
        lineWidth: 1.35,
      },
      {
        type: "polyline",
        points: [{ x: 7, y: 12 }, { x: 11, y: 16 }, { x: 17, y: 8 }],
        lineColor: color,
        lineWidth: 1.25,
      },
    ],
    width: 26,
    height: 27,
  }
}
function paperBrandMark() {
  return {
    canvas: [
      {
        type: "polyline",
        points: [
          { x: 13, y: 0 }, { x: 24, y: 5 }, { x: 22, y: 18 },
          { x: 13, y: 27 }, { x: 4, y: 18 }, { x: 2, y: 5 },
        ],
        closePath: true,
        color: PAPER_THEME.steel,
        lineColor: PAPER_THEME.steel,
        lineWidth: 0.7,
      },
      { type: "ellipse", x: 13, y: 10, r1: 2.4, r2: 2.4, color: PAPER_THEME.white },
      { type: "rect", x: 11.4, y: 12, w: 3.2, h: 6.2, color: PAPER_THEME.white },
    ],
    width: 27,
    height: 28,
  }
}

function paperOrbitGraphic() {
  const dots = []
  for (let row = 0; row < 5; row += 1) {
    for (let column = 0; column < 5; column += 1) {
      dots.push({
        type: "ellipse",
        x: 7 + column * 8,
        y: 10 + row * 8,
        r1: 0.8,
        r2: 0.8,
        color: "#DCE7EC",
      })
    }
  }
  return {
    canvas: [
      ...dots,
      { type: "ellipse", x: 83, y: 73, r1: 68, r2: 68, fillOpacity: 0, lineColor: "#DFE9EE", lineWidth: 0.7 },
      { type: "ellipse", x: 83, y: 73, r1: 52, r2: 52, fillOpacity: 0, lineColor: "#CEDDE5", lineWidth: 0.65 },
      { type: "ellipse", x: 83, y: 73, r1: 36, r2: 36, fillOpacity: 0, lineColor: "#E2EBEF", lineWidth: 0.6 },
      { type: "ellipse", x: 132, y: 26, r1: 3.1, r2: 3.1, color: "#86C5B6" },
      { type: "ellipse", x: 37, y: 103, r1: 2.5, r2: 2.5, color: "#9AB8C8" },
      { type: "ellipse", x: 120, y: 124, r1: 2.1, r2: 2.1, color: "#9AB8C8" },
      {
        type: "polyline",
        points: [
          { x: 83, y: 48 }, { x: 102, y: 56 }, { x: 100, y: 79 },
          { x: 83, y: 95 }, { x: 66, y: 79 }, { x: 64, y: 56 },
        ],
        closePath: true,
        color: PAPER_THEME.steel,
        lineColor: PAPER_THEME.steel,
        lineWidth: 0.7,
      },
      { type: "ellipse", x: 83, y: 66, r1: 3.5, r2: 3.5, color: PAPER_THEME.white },
      { type: "rect", x: 80.6, y: 68, w: 4.8, h: 11, color: PAPER_THEME.white },
    ],
    width: 165,
    height: 145,
  }
}

function paperHero(model, date, copy) {
  return paperPanel([
    {
      columns: [
        {
          stack: [
            { text: "ANALIZA PASYWNA", style: "paperEyebrow" },
            { text: copy.title, style: "paperTitle" },
            { text: text(model.metadata.domain), style: "paperDomain" },
            { text: date ? `Analiza z ${date} r.` : "Data analizy: brak w zapisie.", style: "paperDate" },
            { text: "PODSUMOWANIE ANALIZY", style: "paperOverline", margin: [0, 4, 0, 2] },
            paperParagraph(model.summary.text, "paperBodyMuted"),
          ],
          width: "*",
        },
        paperOrbitGraphic(),
      ],
      columnGap: 6,
    },
  ], PAPER_THEME.border, PAPER_THEME.white, [12, 8, 12, 8], 6)
}


function paperPlural(count, forms) {
  const lastTwo = count % 100
  const last = count % 10
  if (count === 1) return forms[0]
  if (last >= 2 && last <= 4 && (lastTwo < 12 || lastTwo > 14)) return forms[1]
  return forms[2]
}

function paperPriorityLegendItem(key, priority, count) {
  return {
    columns: [
      {
        canvas: [{
          type: "ellipse",
          x: 4,
          y: 5,
          r1: 3.5,
          r2: 3.5,
          color: PAPER_PRIORITY_COLORS[key] || PAPER_THEME.steel,
        }],
        width: 12,
      },
      { text: priority.label, style: "paperSmall", width: "*" },
      { text: String(count), style: "paperCount", width: 18, alignment: "right" },
    ],
    columnGap: 4,
    width: "*",
  }
}

function paperPriorityContent(data) {
  const total = data.areas.length
  const priorities = Object.entries(data.priorities).sort((a, b) => a[1].rank - b[1].rank)
  const barWidth = 468
  const bar = [{ type: "rect", x: 0, y: 0, w: barWidth, h: 12, color: "#E3EBEF" }]
  let x = 0
  if (total) {
    const segmentWidth = barWidth / total
    for (const [key] of priorities) {
      for (const area of data.areas) {
        if (area.priority !== key) continue
        bar.push({
          type: "rect",
          x,
          y: 0,
          w: segmentWidth,
          h: 12,
          color: PAPER_PRIORITY_COLORS[key] || PAPER_THEME.steel,
          lineColor: PAPER_THEME.white,
          lineWidth: 0.55,
        })
        x += segmentWidth
      }
    }
  }
  const legend = []
  for (let index = 0; index < priorities.length; index += 2) {
    legend.push({
      columns: priorities.slice(index, index + 2).map(([key, priority]) =>
        paperPriorityLegendItem(key, priority, data.priorityCounts[key] || 0)
      ),
      columnGap: 14,
      margin: [0, 2, 0, 1],
    })
  }
  return [
    {
      columns: [
        { text: "Priorytety weryfikacji", style: "paperCardTitle" },
        {
          text: `${total} ${paperPlural(total, ["obszar", "obszary", "obszarów"])}`,
          style: "paperCount",
          alignment: "right",
        },
      ],
      margin: [0, 0, 0, 3],
    },
    { text: "Jeden segment odpowiada jednemu obszarowi głównych ustaleń.", style: "paperSmall", margin: [0, 0, 0, 7] },
    { canvas: bar, margin: [0, 0, 0, 7] },
    ...legend,
  ]
}

function paperAreaPanel(data) {
  const content = [
    {
      columns: [
        { text: "Obszary ustaleń", style: "paperCardTitle" },
        { text: "Liczba wariantów w obszarze", style: "paperSmall", alignment: "right" },
      ],
      margin: [0, 0, 0, 6],
    },
  ]
  if (!data.areas.length) {
    content.push({ text: "Brak ustaleń do pogrupowania", style: "paperBodyMuted" })
    return paperPanel(content, PAPER_THEME.border, PAPER_THEME.white, [12, 6, 12, 6], 6)
  }
  for (const area of data.areas) {
    content.push({
      stack: [
        {
          columns: [
            { text: text(area.title), style: "paperArea", width: "*" },
            {
              text: `${area.count} ${paperPlural(area.count, ["wariant", "warianty", "wariantów"])}`,
              style: "paperCount",
              alignment: "right",
              width: 72,
            },
          ],
          columnGap: 8,
        },
        {
          canvas: [
            { type: "rect", x: 0, y: 0, w: 468, h: 4, color: "#DFE8ED" },
            {
              type: "rect",
              x: 0,
              y: 0,
              w: (area.count / data.maximum) * 468,
              h: 4,
              color: PAPER_PRIORITY_COLORS[area.priority] || PAPER_THEME.steel,
            },
          ],
          margin: [0, 1, 0, 3],
        },
      ],
      margin: [0, 0, 0, 1],
    })
  }
  return paperPanel(content, PAPER_THEME.border, PAPER_THEME.white, [12, 6, 12, 6], 6)
}

function lowerFirst(value) {
  const source = String(value || "")
  return source ? source[0].toLocaleLowerCase("pl-PL") + source.slice(1) : ""
}

function paperLeadRecommendation(model) {
  const first = model.brief_cves?.items?.[0]
  if (!first) return model.summary.important_rows[0]?.recommendation || model.summary.action
  return `Sprawdzić wersję ${first.product} ${first.version} i stan poprawek dostawcy; ${lowerFirst(first.recommendation)}`
}

function paperPriorityIcon(priority) {
  return paperShield(priority === "urgent" ? PAPER_THEME.urgent : PAPER_THEME.steel)
}

function paperCveGroupPanel(group) {
  const confidence = unique(group.items.map(item => item.confidence_label)).join(", ") || "nieustalona"
  const backports = unique(group.items.map(item => item.backport_status_label)).join(", ") || "nieustalone"
  const recommendations = new Map()
  for (const item of group.items) {
    const recommendation = item.recommendation?.trim()
    if (!recommendation) continue
    const identifiers = recommendations.get(recommendation) || []
    identifiers.push(item.identifier)
    recommendations.set(recommendation, identifiers)
  }
  const content = [
    {
      columns: [
        {
          stack: [
            { text: "ROZPOZNANY KOMPONENT", style: "paperOverline" },
            { text: `${group.product} ${group.version}`, style: "paperComponent" },
          ],
          width: "*",
        },
        {
          stack: [
            { text: "PEWNOŚĆ DOPASOWAŃ", style: "paperOverline", alignment: "right" },
            { text: confidence, style: "paperMetric", alignment: "right" },
          ],
          width: 118,
        },
      ],
      columnGap: 10,
      margin: [0, 0, 0, 5],
    },
    paperParagraph("Zaobserwowana wersja wymaga weryfikacji po stronie administratora.", "paperBodyMuted"),
    paperParagraph(`Stan poprawek dostawcy: ${backports}`, "paperSmall"),
    { text: `${group.items.length === 1 ? "Jedno" : group.items.length === 2 ? "Dwa" : "Trzy"} potencjalne dopasowania CVE`, style: "paperCardTitle", margin: [0, 2, 0, 4] },
  ]
  for (const item of group.items) {
    content.push(
      {
        columns: [
          { text: item.identifier, style: "paperCveId", width: 122 },
          item.vendor_link
            ? {
                text: [{ text: "Źródło producenta", link: item.vendor_link }],
                style: "paperLink",
                alignment: "right",
                width: "*",
              }
            : { text: "Brak odnośnika producenta w JSON-ie", style: "paperSmall", alignment: "right", width: "*" },
        ],
        columnGap: 8,
        margin: [0, 4, 0, 1],
      },
      paperParagraph(item.explanation, "paperBody"),
      paperParagraph(
        `${briefMatchStatus(item)} · Pewność: ${item.confidence_label || "nieustalona"} · Poprawki dostawcy: ${item.backport_status_label || "nieustalone"}`,
        "paperSmall"
      ),
      {
        canvas: [{
          type: "line",
          x1: 0,
          y1: 0,
          x2: 468,
          y2: 0,
          lineWidth: 0.45,
          lineColor: PAPER_THEME.border,
        }],
        margin: [0, 2, 0, 5],
      }
    )
  }
  if (recommendations.size) {
    content.push({ text: "WSPÓLNE ZALECENIE", style: "paperOverline", margin: [0, 4, 0, 3] })
    for (const [recommendation, identifiers] of recommendations) {
      content.push(paperParagraph(
        `${recommendations.size > 1 ? `${identifiers.join(", ")}: ` : ""}${recommendation}`,
        "paperRecommendation"
      ))
    }
  }
  return { unbreakable: true, stack: [paperPanel(content)] }
}

function paperCveSection(model, groups) {
  if (!groups.length) return []
  const firstGroup = paperCveGroupPanel(groups[0])
  const note = model.brief_cves?.note
    ? [paperPanel([paperParagraph(model.brief_cves.note, "paperBodyMuted")], PAPER_THEME.border, PAPER_THEME.white)]
    : []
  return [
    { ...paperSectionLabel("USTALENIA PRIORYTETOWE"), pageBreak: "before" },
    { text: groups.length === 1 ? `Środowisko ${groups[0].product}` : "Komponenty do sprawdzenia", style: "paperPageTitle", headlineLevel: 2 },
    ...note,
    firstGroup,
    ...groups.slice(1).map(paperCveGroupPanel),
  ]
}

function paperObservationCard(item) {
  const content = [
    {
      columns: [
        paperPriorityIcon(item.priority),
        {
          stack: [
            { text: item.groupTitle, style: "paperSmall" },
            { text: item.title, style: "paperCardTitle" },
          ],
          width: "*",
        },
      ],
      columnGap: 8,
      margin: [0, 0, 0, 5],
    },
    { text: "ZAOBSERWOWANO", style: "paperOverline", margin: [0, 1, 0, 3] },
    ...(item.observation ? [paperParagraph(item.observation)] : []),
    ...(item.recommendation
      ? [
          { text: "DO SPRAWDZENIA", style: "paperOverline", margin: [0, 1, 0, 3] },
          paperParagraph(item.recommendation, "paperRecommendation"),
        ]
      : []),
  ]
  return { unbreakable: true, stack: [paperPanel(content)] }
}

function paperObservationSection(observations) {
  if (!observations.items.length) return []
  const firstCard = paperObservationCard(observations.items[0])
  const intro = `${observations.items.length} ${paperPlural(observations.items.length, ["obserwacja", "obserwacje", "obserwacji"])} z tego skanu; poniżej wskazano, co administrator może sprawdzić.`
  const nodes = [
    {
      stack: [
        paperSectionLabel("POZOSTAŁE OBSERWACJE"),
        { text: "Pozostałe ustalenia", style: "paperPageTitle", headlineLevel: 2 },
        paperParagraph(intro, "paperBodyMuted"),
        firstCard,
      ],
      unbreakable: true,
    },
    ...observations.items.slice(1).map(paperObservationCard),
  ]
  if (observations.omittedAreas.length) {
    nodes.push(paperParagraph(
      `Pełny przegląd obejmuje również uwagi w obszarach: ${observations.omittedAreas.join(", ")}.`,
      "paperSmall"
    ))
  }
  return nodes
}

function paperScopePage(model, date) {
  const brand = model.copy.brand
  const company = brand.legal_name || "Codefellow Sp. z o.o."
  const email = brand.email
    ? { text: [{ text: brand.email, link: `mailto:${brand.email}` }], style: "paperContact" }
    : paperParagraph("Brak adresu e-mail w konfiguracji.", "paperSmall")
  const phone = brand.phone
    ? { text: brand.phone, style: "paperContact" }
    : paperParagraph("Brak numeru telefonu w konfiguracji.", "paperSmall")
  return [{
    stack: [
      paperSectionLabel("CODEFELLOW SCOUT"),
      { text: "Zakres i kontakt", style: "paperPageTitle", headlineLevel: 2 },
      { text: date ? `Analiza z ${date} r.` : "Data analizy: brak w zapisie.", style: "paperSubtitle" },
      paperPanel([
        { text: "ZAKRES ANALIZY", style: "paperOverline" },
        paperParagraph(`Raport obejmuje wybrane obserwacje z pasywnej analizy publicznie dostępnej strony ${model.metadata.domain}. Wnioski opierają się na informacjach przekazywanych przez serwis.`),
      ]),
      paperPanel([
        { text: "JAK INTERPRETOWAĆ WYNIKI", style: "paperOverline" },
        paperParagraph("Dokument ma charakter informacyjny i nie stanowi pełnego audytu bezpieczeństwa. Dopasowania CVE wymagają potwierdzenia wersji pakietów, stanu poprawek i warunków występowania podatności."),
        paperParagraph(`Raport przygotowała firma ${company} przy użyciu narzędzia Codefellow Scout.`, "paperBodyMuted"),
      ], PAPER_THEME.border, PAPER_THEME.white),
      paperSectionLabel("KONTAKT W SPRAWIE RAPORTU"),
      { text: company, style: "paperCompany" },
      {
        columns: [
          { stack: [{ text: "E-MAIL", style: "paperOverline" }, email], width: "*" },
          { stack: [{ text: "TELEFON", style: "paperOverline" }, phone], width: 175 },
        ],
        columnGap: 12,
        margin: [0, 3, 0, 0],
      },
    ],
    pageBreak: "before",
    unbreakable: true,
  }]
}

function paperBackground(_page, size) {
  return {
    canvas: [
      { type: "rect", x: 0, y: 0, w: size.width, h: size.height, color: PAPER_THEME.white },
      { type: "rect", x: 0, y: 0, w: size.width, h: 5, color: PAPER_THEME.steel },
      { type: "rect", x: 0, y: 5, w: size.width * 0.3, h: 2, color: PAPER_THEME.paleBlue },
    ],
  }
}

function paperHeader(domain) {
  return {
    columns: [
      paperBrandMark(),
      { text: "Codefellow Scout", style: "paperHeaderBrand", width: 145 },
      { text: text(domain), style: "paperHeaderDomain", alignment: "right", width: "*" },
    ],
    columnGap: 7,
    margin: [44, 23, 44, 0],
  }
}

function paperFooter(domain, currentPage, pageCount) {
  return {
    stack: [
      {
        canvas: [{
          type: "line",
          x1: 0,
          y1: 0,
          x2: 507,
          y2: 0,
          lineWidth: 0.55,
          lineColor: PAPER_THEME.border,
        }],
      },
      {
        columns: [
          { text: text(`Codefellow Scout / ${domain}`), style: "paperFooter", width: "*" },
          {
            text: `${String(currentPage).padStart(2, "0")} / ${String(pageCount).padStart(2, "0")}`,
            style: "paperFooter",
            alignment: "right",
            width: 56,
          },
        ],
        margin: [0, 7, 0, 0],
      },
    ],
    margin: [44, 11, 44, 0],
  }
}

function briefWhiteDocumentDefinition(model) {
  const metadata = model.metadata
  const copy = model.copy.report
  const date = metadata.scanned_at
    ? new Intl.DateTimeFormat("pl-PL", {
        dateStyle: "long",
        timeZone: metadata.timezone,
      }).format(new Date(metadata.scanned_at))
    : null
  const data = dashboardData(model)
  const cveGroups = briefCveGroups(model)
  const observations = briefObservations(model)
  const urgent = model.findings.some(finding => finding.priority === "urgent")
  const nodes = [
    paperHero(model, date, copy),
    { ...paperSectionLabel("ROZKŁAD PRIORYTETÓW"), margin: [0, 6, 0, 5] },
    paperPanel(paperPriorityContent(data), PAPER_THEME.border, PAPER_THEME.white, [12, 8, 12, 8], 6),
    { ...paperSectionLabel("OBSZARY USTALEŃ"), margin: [0, 6, 0, 5] },
    paperAreaPanel(data),
    paperPanel([
      { text: "W PIERWSZEJ KOLEJNOŚCI", style: "paperCardTitle", color: urgent ? PAPER_THEME.urgent : PAPER_THEME.steel },
      paperParagraph(paperLeadRecommendation(model), "paperRecommendation"),
    ], urgent ? PAPER_THEME.urgent : PAPER_THEME.steel, PAPER_THEME.paleBlue, [12, 7, 12, 7], 6),
  ]
  nodes.push(
    ...paperCveSection(model, cveGroups),
    ...paperObservationSection(observations),
    ...paperScopePage(model, date)
  )
  return {
    pageSize: "A4",
    pageMargins: [44, 82, 44, 56],
    info: {
      title: `${copy.title} — ${metadata.domain}`,
      author: "Codefellow Sp. z o.o.",
      subject: "Skrócona analiza zapisanych obserwacji pasywnych",
    },
    defaultStyle: {
      font: "Roboto",
      color: PAPER_THEME.graphite,
      fontSize: 9.3,
      lineHeight: 1.2,
    },
    background: paperBackground,
    header: () => paperHeader(metadata.domain),
    footer: (currentPage, pageCount) => paperFooter(metadata.domain, currentPage, pageCount),
    styles: {
      paperHeaderBrand: { fontSize: 14, bold: true, color: PAPER_THEME.graphite, margin: [0, 4, 0, 0] },
      paperHeaderDomain: { fontSize: 7.2, color: PAPER_THEME.muted, margin: [0, 8, 0, 0] },
      paperFooter: { fontSize: 6.8, color: PAPER_THEME.muted },
      paperEyebrow: { fontSize: 8, bold: true, characterSpacing: 1.1, color: PAPER_THEME.steel, margin: [0, 0, 0, 4] },
      paperTitle: { fontSize: 26, bold: true, color: PAPER_THEME.graphite, lineHeight: 1.04, margin: [0, 0, 0, 5] },
      paperDomain: { fontSize: 16, bold: true, color: PAPER_THEME.steel, margin: [0, 0, 0, 5] },
      paperDate: { fontSize: 8.5, bold: true, color: PAPER_THEME.graphite, margin: [0, 3, 0, 0] },
      paperOverline: { fontSize: 7, bold: true, characterSpacing: 0.55, color: PAPER_THEME.steel },
      paperSection: { fontSize: 8, bold: true, characterSpacing: 0.7, color: PAPER_THEME.steel, margin: [0, 1, 0, 0] },
      paperPageTitle: { fontSize: 19, bold: true, color: PAPER_THEME.graphite, margin: [0, 3, 0, 8] },
      paperCardTitle: { fontSize: 10.3, bold: true, color: PAPER_THEME.graphite, margin: [0, 0, 0, 3] },
      paperArea: { fontSize: 8.4, color: PAPER_THEME.graphite },
      paperCount: { fontSize: 8, bold: true, color: PAPER_THEME.graphite },
      paperSmall: { fontSize: 7.6, color: PAPER_THEME.muted, lineHeight: 1.15 },
      paperBody: { fontSize: 9, color: PAPER_THEME.graphite, lineHeight: 1.2 },
      paperBodyMuted: { fontSize: 8.7, color: PAPER_THEME.muted, lineHeight: 1.2 },
      paperComponent: { fontSize: 15, bold: true, color: PAPER_THEME.graphite, margin: [0, 2, 0, 0] },
      paperMetric: { fontSize: 9, bold: true, color: PAPER_THEME.steel, margin: [0, 2, 0, 0] },
      paperCveId: { fontSize: 9, bold: true, color: PAPER_THEME.graphite },
      paperLink: { fontSize: 8.2, color: PAPER_THEME.steel, decoration: "underline" },
      paperRecommendation: { fontSize: 9, bold: true, color: PAPER_THEME.graphite, lineHeight: 1.2 },
      paperSubtitle: { fontSize: 9, bold: true, color: PAPER_THEME.steel, margin: [0, 0, 0, 11] },
      paperCompany: { fontSize: 12, bold: true, color: PAPER_THEME.graphite, margin: [0, 0, 0, 9] },
      paperContact: { fontSize: 9, bold: true, color: PAPER_THEME.steel, margin: [0, 3, 0, 0] },
    },
    content: nodes,
  }
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
    const hasCves = briefCveGroups(model).length > 0
    const company = model.copy.brand.legal_name || "Codefellow Sp. z o.o."
    nodes.push(paragraph(
      `Raport przygotowany przez ${company} przy użyciu narzędzia ${brand.name}`,
      "small"
    ))
    if (hasCves) {
      const observations = briefObservations(model)
      nodes.push(
        ...briefCveSection(model),
        ...briefObservationSection(observations),
        ...briefScopeAndContact(model, observations.items.length ? 4 : 3)
      )
    } else {
      nodes.push(...briefScopeAndContact(model, 2, false))
    }
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

export async function renderBriefModel(model, white = false) {
  return renderDefinition(
    white ? briefWhiteDocumentDefinition(model) : briefDocumentDefinition(model)
  )
}
