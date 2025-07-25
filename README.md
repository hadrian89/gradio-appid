# Welcome to FastAPI with integrated AppId

Welcome to the **FastAPI with integrated AppId** repository! 

## 🛠️ Prerequisites

Before you start, ensure you have the following installed:

- Python (>=3.10 recommended)
- pip package manager
- Git (to clone the repository)

---

## 📥 Setup Instructions

1. Verify Python installation and create virtual environment

```bash
python --version
python -m venv env1
source env1/Scripts/activate
```

2. Install the required packages available in the git repo in a file "requirements.txt. Install all the required packages using the below command.

```bash
pip install -r requirements.txt
```

3. run below command to start server

```bash
uvicorn app.main:app --reload --port 8000
```

or if you want to docker file then run below command

```bash
docker build -t gradio-appid .
```

```bash
docker run -p 8000:8000 gradio-appid
```
