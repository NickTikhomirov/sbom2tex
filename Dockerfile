FROM texlive/texlive:TL2025-historic

WORKDIR /app
COPY ./src ./src/
COPY ./main.py .

ENTRYPOINT ["python3", "./main.py", "--compile"]
