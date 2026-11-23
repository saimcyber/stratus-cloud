# Rebuilding the docs

Scripts used to produce the screenshots, the PDF report and the slide deck. They need the app running locally (`scripts/run_services.py` + `npm run dev`) and Microsoft Edge installed.

```bash
npm install playwright-core pptxgenjs jszip sharp react react-dom react-icons  # in a scratch folder
node capture.mjs <repo>/docs/img                                           # screenshots
node pdf.mjs <repo>/docs/report/report.html <repo>/docs/Stratus-Technical-Report.pdf
node deck.js <repo>                                                        # docs/Stratus-Presentation.pptx
```
