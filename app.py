from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

# Sample data for demonstration
data = {
    'IP': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
    'Status': ['Active', 'Inactive', 'Active'],
    'Location': ['New York', 'Los Angeles', 'Chicago']
}

df = pd.DataFrame(data)

@app.route('/')
def dashboard():
    return render_template('dashboard.html', tables=[df.to_html(classes='data')], titles=df.columns.values)

if __name__ == '__main__':
    app.run(debug=True)