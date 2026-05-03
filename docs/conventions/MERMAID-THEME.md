# RealWork Labs — Mermaid.js Brand Theme

Extracted from [realworklabs.com](https://realworklabs.com).

## Brand Palette

| Role              | Name           | Hex       | Usage                          |
| ----------------- | -------------- | --------- | ------------------------------ |
| Primary           | Blue           | `#2D72F7` | Links, borders, accents        |
| Primary Dark      | Dark Blue      | `#08103D` | Headings, dark backgrounds     |
| Primary Darkest   | Navy           | `#00072D` | Body text on light backgrounds |
| Surface Dark      | Near-Black     | `#0D0D12` | Tertiary/dark backgrounds      |
| Accent            | Lime           | `#CFFF04` | CTAs, highlights               |
| Accent Alt        | Yellow-Green   | `#B5DD08` | Secondary highlights           |
| Neutral Light     | Light Gray     | `#F8F9FB` | Section backgrounds            |
| Neutral Border    | Border Gray    | `#DFE1E7` | Dividers, card borders         |
| Neutral Text      | Mid Gray       | `#666D80` | Secondary body text            |
| Error             | Red            | `#FF443D` | Error states                   |
| White             | White          | `#FFFFFF` | Backgrounds, text on dark      |

## Mermaid Theme Configuration

Use this `init` directive at the top of any Mermaid diagram:

```text
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor':       '#F8F9FB',
    'primaryTextColor':   '#00072D',
    'primaryBorderColor': '#2D72F7',
    'secondaryColor':     '#F8F9FB',
    'secondaryTextColor': '#00072D',
    'secondaryBorderColor':'#DFE1E7',
    'tertiaryColor':      '#F8F9FB',
    'tertiaryTextColor':  '#00072D',
    'tertiaryBorderColor':'#DFE1E7',
    'lineColor':          '#08103D',
    'textColor':          '#00072D',
    'clusterBkg':         '#F8F9FB',
    'clusterBorder':      '#DFE1E7',
    'titleColor':         '#08103D',
    'edgeLabelBackground':'#FFFFFF',
    'fontFamily':         'Inter, Plus Jakarta Sans, sans-serif',
    'fontSize':           '14px'
  }
}}%%
```

## Node Class Helpers

Always include these `classDef` declarations in diagrams:

```text
classDef primary fill:#2D72F7,stroke:#08103D,color:#FFFFFF
classDef dark    fill:#08103D,stroke:#00072D,color:#FFFFFF
classDef accent  fill:#CFFF04,stroke:#B5DD08,color:#00072D
classDef neutral fill:#F8F9FB,stroke:#DFE1E7,color:#00072D
classDef error   fill:#FF443D,stroke:#FF443D,color:#FFFFFF
```
