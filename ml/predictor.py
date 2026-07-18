import joblib

# Load trained model
model = joblib.load("ml/anomaly_model.pkl")


def predict_log(failed_login,
                sql_injection,
                admin_login,
                suspicious_ip,
                requests):

    features = [[
        failed_login,
        sql_injection,
        admin_login,
        suspicious_ip,
        requests
    ]]

    prediction = model.predict(features)

    if prediction[0] == -1:
        return "ANOMALY"

    return "NORMAL"
