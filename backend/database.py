import mysql.connector

def get_db():
    return mysql.connector.connect(
        host="localhost",
        port=3306,
        user="root",
        password="dbms123456789@#",
        database="ai_social_security"
    )
