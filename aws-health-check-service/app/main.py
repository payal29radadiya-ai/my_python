from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import yaml

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/upload")
async def upload_yaml(file: UploadFile = File(...)):
    steps = []
    health_report = {}

    # Step 1: File validation
    if not file.filename.endswith((".yml", ".yaml")):
        return JSONResponse({
            "steps": [{"status": "error", "message": "Invalid file type"}],
            "health_report": {}
        })

    steps.append({"status": "success", "message": "File type validated"})

    # Step 2: Read YAML
    try:
        content = await file.read()
        yaml_data = yaml.safe_load(content)
        steps.append({"status": "success", "message": "YAML parsed successfully"})
    except Exception as e:
        return JSONResponse({
            "steps": [{"status": "error", "message": f"YAML parsing failed: {e}"}],
            "health_report": {}
        })

    # Step 3: Extract AWS services
    aws_services = set()

    if not aws_services:
        steps.append({"status": "error", "message": "No AWS services found in YAML"})
        return {"steps": steps, "health_report": {}}

    steps.append({"status": "success", "message": f"AWS services extracted: {list(aws_services)}"})

    steps.append({"status": "success", "message": "Health check completed"})

    return {
        "steps": steps,
        "health_report": health_report
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080)