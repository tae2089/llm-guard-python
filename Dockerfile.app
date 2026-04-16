# 테스트용 앱 이미지 — llm-guard 의존성 없음
FROM python:3.13-slim
RUN pip install requests --quiet
COPY tests/k8s_demo.py /app/
WORKDIR /app
CMD ["python", "k8s_demo.py"]
