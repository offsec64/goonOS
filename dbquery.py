import requests
import os
import mysql.connector

from dotenv import load_dotenv

load_dotenv()
DB_HOST = os.getenv("DB_HOST")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")

def query_steamstats_database(table, rows=2):

    #Connect to the MySQL database
    mydb = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USERNAME,
        password=DB_PASSWORD,
        database="goontech"
    )

    # Check if the database connection was successful
    if mydb.is_connected():
        print("Connected to the database successfully!")
    else:
        print("Failed to connect to the database.")
        mydb.close()
        raise ConnectionError("Could not connect to the MySQL database. Please check your credentials and network connection.")

    mycursor = mydb.cursor()

    # Selects the most recent entry from the steam_data table
    mycursor.execute(f"SELECT * FROM `{table}` ORDER BY `timestamp` DESC LIMIT {rows}")
    databaseResult = mycursor.fetchall()

    if databaseResult:
        print(f"Most recent entry in {table}:")
        for row in databaseResult:
            print(row[3] + " Hours @ " + row[4] + " UTC")
    else:
        print(f"No entries found in '{table}' table.")

    mycursor.close()
    mydb.close()

    latestHours = int(databaseResult[0][3])
    previousHours = int(databaseResult[1][3])
    delta = latestHours - previousHours

    returnDict = {"name": databaseResult[0][2], "hours": latestHours, "delta": delta}

    return returnDict
