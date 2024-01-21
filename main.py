from flask import Flask, render_template, request, session
from CheckIP import CheckIP

app = Flask(__name__, template_folder='templates')

checkings = []

@app.route('/', methods=['GET'])
def check():
    return render_template('index.html')

@app.route('/result', methods=['POST'])
def result():
    if request.method == "GET":
        return render_template('error.html', message="Method not allowed")

    if request.method == "POST":
        input = request.values.get('input')
        if input == "":
            return render_template('result.html')

        input_type = request.values.get('select')
        domain = ""
        if input_type == "domain":
            domain = input
            try:
                checking = CheckIP(input, isDomain=True)
            except:
                return render_template('error.html', message="Domain is not valid")
        if input_type == "ip":
            if(CheckIP(input, isDomain=False).information_from_whois() == "none"):
                return render_template('error.html', message="IP is not valid")
            checking = CheckIP(input, isDomain=False)


        checkings.append({"ip": checking.ip,
                          "IsMalicious": "Zararlı" if checking.IsMalicious == True else "Zararlı Değil",
                          "IsMaliciousBool": checking.IsMalicious.__str__(),
                          "EnumerationResult": checking.EnumerationResult,
                          "Country": checking.country if checking.country != "" else "none",
                            "ASN": checking.asn if checking.asn != "" else "none",
                            "Type": checking.type if checking.type != "" else "none",
                          "Domain": domain if domain != "" else "none",
                          })



    print(len(checkings))
    return render_template('result.html', data=checkings[-1])


@app.route('/stats', methods=['GET'])
def stats():
    if checkings == []:
        return render_template('error.html', message="There is no checking to show")
    isMaliciousCount = len([elem for elem in checkings if elem["IsMaliciousBool"] == "True"])
    isNotMaliciousCount = len([elem for elem in checkings if elem["IsMaliciousBool"] == "False"])
    return render_template('stats.html', data=checkings, isMallwareCount=isMaliciousCount, isNotMallwareCount=isNotMaliciousCount)


if __name__ == '__main__':
    app.run(debug=True)



