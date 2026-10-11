# Eleventh Seal Console

LOVABLE MASTER PROMPT

THE SILENT CONCH: THE ELEVENTH SEAL

Ultra-Hard Cybersecurity CTF — Production-Quality Frontend

Build a complete, polished, fully functional frontend for The Silent Conch: The Eleventh Seal, an Ultra Hard CTF challenge designed for experienced cybersecurity specialists.

This is a fictional intelligence investigation platform set in the Kurukshetra CTF universe. The challenge combines Web Exploitation, Digital Forensics, Cryptography, and LLM/Agent Security.

Your job is to create a bespoke, professionally art-directed cybersecurity application that feels like a real tool built by a highly skilled product engineering team.

The most important requirement: the website must NOT look AI-generated.

Do not build a generic SaaS landing page, AI dashboard, ChatGPT clone, or stereotypical neon hacker interface. Design an original visual system with strong typography, careful composition, meaningful density, precise spacing, and restrained colors.

Implement a working application, not a static mockup.

1. TECHNICAL REQUIREMENTS

Use the following frontend stack:

React

TypeScript

Vite

Tailwind CSS

shadcn/ui only where appropriate

Lucide icons for functional interface icons

Use the existing repository's frontend stack if this project has already been imported with a working configuration.

The backend is a separate FastAPI application. Connect the frontend to that backend through its existing HTTP API.

Before implementing the UI, inspect the connected repository and identify the available API routes, request schemas, response formats, authentication requirements, and error responses.

Known endpoint examples from the existing challenge include:

GET /api/diagnostics/download

POST /api/oracle/query

POST /api/archive/redeem

Verify these routes and their exact request and response contracts from the existing implementation before using them.

Use VITE_API_BASE_URL for backend configuration. Use relative URLs when the frontend and backend are deployed under the same origin.

Do not introduce Supabase, Firebase, another database, a replacement backend, or an unnecessary AI service. The existing backend remains authoritative for challenge state, authentication, document retrieval, agent execution, ticket management, and flag delivery.

If the repository is not connected or its API contracts are unavailable, isolate API integration behind a typed service layer and clearly identify the configuration required. Do not invent successful API responses or pretend the integration has been verified.

2. DESIGN DIRECTION

Product identity

Product name: THE SILENT CONCH

Subtitle: THE ELEVENTH SEAL

Organization: KURUKSHETRA RELAY AUTHORITY

System designation: SEALED INTELLIGENCE SYSTEM

Incident designation: DAY XI

The interface represents a fictional intelligence relay whose sealed archive is under investigation.

The historical setting must be subtle. The interface should resemble a modern intelligence operations and forensic investigation platform, with restrained archival details—not a fantasy game or mythology-themed landing page.

Visual characteristics

The design should feel:

Deliberate and editorial.

Technically credible.

Dense but easy to navigate.

Restrained rather than flashy.

Functional rather than decorative.

Custom-designed rather than template-based.

Use a compact navigation header, asymmetrical but disciplined layouts, fine dividers, clear information hierarchy, structured tables, and carefully aligned technical metadata.

Do not place every section inside a rounded card. Use a mixture of open layouts, table regions, section dividers, compact panels, and selected bordered surfaces.

Create a distinctive visual identity using spacing, typography, borders, background tones, and small geometric details.

Color system

Start with these design tokens and refine them consistently:

Background: #101311

Primary surface: #171C19

Secondary surface: #1D2420

Borders: #303A33

Primary text: #E7E9E2

Secondary text: #A1AAA1

Muted text: #737E75

Main accent: #8DAF9A

Information accent: #87A9BC

Warning: #D1A365

Error: #C87870

Use colors to indicate meaningful states, such as authentication failures, successful requests, warnings, and unavailable records. Do not decorate every component with a bright accent.

Typography

Use a polished sans-serif typeface for primary interface content and a monospace typeface for technical data.

Preferred stacks:

UI: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif

Technical: "SFMono-Regular", Consolas, "Liberation Mono", monospace

Optional editorial accent: Georgia, "Times New Roman", serif

Use a locally available font or a dependable fallback. Do not make the application dependent on an external font service.

Establish a clear hierarchy between page titles, section titles, field labels, explanatory text, identifiers, timestamps, protocol values, request output, and logs.

Absolutely avoid

Purple and blue gradient backgrounds.

Glassmorphism.

Glowing borders around every panel.

Floating blobs and particle effects.

AI stars, sparkles, robot mascots, and chatbot avatars.

Excessive rounded cards and pill-shaped controls.

Giant marketing headlines.

Fake cybersecurity statistics.

Fake terminal output.

Fake network activity.

Decorative analytics charts.

Generic AI-generated copy.

Unnecessary animations and typewriter effects.

The final result should look like a real specialized security product.

3. GLOBAL APPLICATION SHELL

Build a persistent application shell with a compact header and meaningful navigation.

The header should include:

An original geometric relay insignia.

KURUKSHETRA RELAY AUTHORITY

SEALED INTELLIGENCE SYSTEM

A small DAY XI designation.

Navigation to the available application sections.

A service-status indicator only if backed by real status information.

Create the insignia using a small inline SVG or CSS geometry. Do not use emojis or generic AI icons.

Use a compact, carefully aligned layout. Navigation must remain usable on mobile.

Create these main sections:

Command Overview

Diagnostic Records

Oracle Console

Archive Redemption

Do not add a step-by-step exploitation wizard. Participants must discover the challenge's solution themselves.

4. COMMAND OVERVIEW

Design an operational overview for the sealed intelligence incident.

Use the heading:

THE SILENT CONCH

THE ELEVENTH SEAL

Supporting text:

"An intelligence relay incident remains under investigation. Examine the available records and establish the validity of the sealed archive request."

Include a structured layout with:

Incident identification.

Diagnostic record availability.

Oracle access status.

Current session state, if available.

Archive redemption interface or navigation.

Relevant records supplied by the backend.

Do not display invented threat scores, false uptime, fake active-user counts, fabricated packet totals, or made-up telemetry.

Any dynamic information must come from the backend. If a metric is unavailable, omit it or clearly represent it as unavailable.

Use compact section headers, restrained dividers, and a carefully composed information hierarchy. Do not turn the page into a grid of identical statistic cards.

5. DIAGNOSTIC RECORDS

Build a professional evidence register using actual backend data.

Where available, display:

Record identifier.

Record type.

Classification.

Timestamp.

Availability.

Brief description.

Available action.

Use aligned columns, small but readable metadata, restrained status colors, subtle row highlighting, and fine borders.

Records should be presented in a forensic inventory style rather than a storefront-style collection of cards.

Implement:

Initial loading states.

Empty states.

Request failures.

Record inspection.

Download controls supported by the existing backend.

Clear server-derived error messages.

Connect every control to the real endpoint.

The existing challenge contains an intentional HTTP parameter pollution vulnerability in the diagnostic download flow. Preserve the backend behavior without modifying the challenge's security logic.

Do not create a second endpoint or alternate route that bypasses the intended vulnerability.

Do not reveal the intended exploit through explicit instructional text on the UI.

The interface should allow players to investigate the records. It must not solve the CTF for them.

6. EVIDENCE INSPECTION

Create a dedicated evidence-inspection presentation for the artifacts exposed by the application.

Use a technical, report-oriented design that supports:

Structured record information.

Protocol identifiers.

Evidence metadata.

Timestamps.

Request results.

Server-returned diagnostic messages.

Expandable technical details where useful.

Render actual backend information instead of fabricated network traffic, cryptographic values, packet histories, or forensic conclusions.

Use monospace fonts for technical values and conventional typography for explanations.

Do not produce fake packet visualizations or animated scanning effects.

The PCAP investigation must remain a real technical challenge solved using appropriate external forensic tools.

7. ORACLE CONSOLE — NOT A CHATBOT

This section is particularly important.

The Oracle is an intelligence query system with retrieval and tool-execution behavior. Do not design it as a ChatGPT clone.

There must be no conventional chat bubbles, assistant avatar, large centered conversational prompt, floating AI icon, or generic "Ask me anything" interface.

Instead, build a structured INTELLIGENCE QUERY CONSOLE.

Use three deliberate regions where screen width permits:

Session and authorization region

Include the relevant authentication input, current session status, and supported case information.

Query workspace

Provide a clearly labeled text input or textarea, a submission button, and a compact explanation of what the query interface accepts.

Results and execution region

Display the actual server response, retrieved document references, metadata, and tool-execution information if those fields are returned by the backend.

Represent output as structured investigation records, report sections, or transcript entries rather than chat bubbles.

Implement:

Real query submission.

Authentication handling.

Loading state.

Invalid-token feedback.

Server validation errors.

Successful response rendering.

Empty results.

Network failures.

Repeat submission without duplicated requests.

Copy controls for technical values where appropriate.

Use the existing API request format. Do not invent authentication mechanisms or change the server's JWT requirements.

If the existing backend requires a bearer token, send it using the correct authorization header.

Do not implement cryptographic key recovery or privileged token signing in the frontend. The intended cryptographic investigation belongs to the challenge itself.

Never hardcode the canonical flag, private signing key, a privileged JWT, an archive ticket, or a solved query.

Do not simulate agent responses when the server is unavailable.

Render agent responses and retrieved documents as untrusted text by default. Do not inject arbitrary returned HTML into the browser.

8. ARCHIVE REDEMPTION

Create a dedicated section called:

SEALED ARCHIVE

Subtitle: AUTHORIZATION & REDEMPTION

The section should be restrained, precise, and operational. Do not use gamified treasure chests, glowing lock icons, or dramatic cinematic animations.

Include only functionality supported by the existing backend:

Session or authorization information.

Case identifier where appropriate.

Archive ticket input.

Redemption action.

Actual request status.

Success or failure response.

Integrate the existing POST /api/archive/redeem endpoint if that route is confirmed in the source code.

Follow its exact request schema and required authorization header.

Handle invalid, expired, replayed, and incorrectly bound tickets according to the actual backend response.

Display the flag only when the real server returns it following successful redemption.

Do not add a client-side success shortcut or display a sample flag.

Never include the canonical flag in HTML, JSX, JavaScript constants, client configuration, or a bundled asset.

The flag must be supplied exclusively by the existing server-side redemption process.

9. API INTEGRATION ARCHITECTURE

Create a small and maintainable API service layer.

Suggested organization:

src/services/api.ts

src/services/diagnostics.ts

src/services/oracle.ts

src/services/archive.ts

src/types/api.ts

src/components/layout/

src/components/diagnostics/

src/components/oracle/

src/components/archive/

src/pages/

Adapt the layout to the existing project rather than blindly creating duplicate structures.

Requirements:

Centralize the API base URL.

Use typed request and response interfaces based on the real API contracts.

Handle JSON parsing and non-JSON error responses safely.

Respect HTTP status codes.

Prevent duplicate submissions while requests are pending.

Display helpful error feedback.

Avoid hardcoded success responses.

Avoid persisting privileged session data unnecessarily.

Never log bearer tokens or secret values.

Use same-origin requests where appropriate.

Document CORS or deployment configuration only if required.

Use VITE_API_BASE_URL for an independently hosted FastAPI service. Never put private API credentials or server-side secrets in VITE_ variables.

Do not add a mock backend or make Supabase the source of truth.

If integration cannot be tested because the backend is unavailable, provide an isolated API layer and clearly document the unverified connection. Do not claim the application is fully integrated.

10. RESPONSIVE BEHAVIOR

The application must work on desktop, laptop, tablet, and mobile.

Desktop:

Compact global header.

Purposeful multi-column workspace.

Adequate space for forensic data and result output.

Consistent page gutters and alignment.

Minimal unnecessary scrolling.

Tablet:

Reduced column count.

Preserved information hierarchy.

Navigable diagnostic tables.

Mobile:

Collapsible navigation.

Stacked workspaces.

Horizontally scrollable tables when necessary.

Inputs and buttons sized for touch interaction.

No accidental horizontal page overflow.

Do not simply shrink the desktop layout. Recompose it for smaller screens.

11. ACCESSIBILITY AND IMPLEMENTATION QUALITY

Use semantic HTML, visible keyboard focus indicators, appropriate contrast, properly associated labels, accessible status messages, and keyboard-operable controls.

Respect prefers-reduced-motion.

Keep components small and understandable.

Use a coherent spacing system and CSS variables or Tailwind theme tokens for the design system.

Avoid huge components containing the entire application.

Avoid inline event handlers and unsafe DOM operations.

Treat query output, retrieved documents, error messages, and user inputs as untrusted content.

Use safe React text rendering by default. Do not use dangerouslySetInnerHTML for server responses.

Do not introduce unnecessary libraries or dependencies.

12. DELIVERY AND TESTING

Implement the entire frontend and test its behavior.

Verify:

The application loads without JavaScript errors.

Navigation functions correctly.

Diagnostic records use real backend data.

Diagnostic downloads call the existing API.

The intended backend HPP vulnerability remains unchanged.

The Oracle console sends requests using the actual API contract.

Invalid authentication produces the correct error state.

Successful Oracle responses display actual server data.

Adversarial retrieved content cannot execute frontend scripts.

Archive redemption sends the correct request.

Rejected and replayed tickets display actual server responses.

Successful redemption displays only the flag returned by the server.

No secret, private key, privileged token, or canonical flag has been added to frontend assets.

There are no fake success states or mocked operational metrics.

Responsive layouts work at common desktop and mobile widths.

Keyboard navigation and visible focus states work.

The browser console contains no unexplained errors.

The frontend does not require a paid model API to run.

Existing backend functionality and CTF behavior remain unchanged.

Do not claim an endpoint or complete workflow has been tested when the backend was unavailable.

If the frontend is intended to be deployed separately from FastAPI, document the API base URL and required CORS settings without exposing server secrets.

13. FINAL VISUAL REFINEMENT

After implementation, review the complete rendered website.

Perform a second refinement pass specifically looking for generic AI-generated design patterns.

Ask:

Does the interface have a recognizable identity?

Does it resemble a professional investigation console?

Are tables and technical outputs genuinely useful?

Is the typography hierarchy deliberate?

Are the colors restrained?

Is the page composition varied without being inconsistent?

Are there too many cards, badges, rounded surfaces, or decorations?

Do all operational controls perform real actions?

Does the application remain usable on mobile?

Does the UI preserve the challenge's difficulty?

Remove generic components and unnecessary visual decoration. Improve spacing, density, alignment, and visual hierarchy wherever required.

Final instruction

Build the actual application in this Lovable project.

Prioritize a bespoke visual identity, a professional forensic investigation experience, correct integration with the existing FastAPI API, safe rendering of untrusted content, and reliable interactions.

Do not stop at a polished-looking mockup. Build a working frontend whose behavior is backed by the real challenge server.

The finished result must feel deliberately designed by an expert product team—not generated from a generic AI dashboard template.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/017a8b20-7bd0-51fc-a309-54853d1250d6).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
