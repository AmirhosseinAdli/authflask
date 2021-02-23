FROM python:3.8-alpine
WORKDIR /authflask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
COPY requirements.txt requirements.txt
#RUN pip install -U pip==9.0.3
RUN pip install -r requirements.txt
EXPOSE 5000
COPY . .
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
