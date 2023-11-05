import os
import tempfile
import subprocess
from flask import Flask, request, render_template
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.apk import ARSCParser
from androguard.misc import AnalyzeAPK
from androguard.core.androconf import show_logging
import logging

# Enable logging to see verbose output
show_logging(level=logging.INFO)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def upload_and_analyze_apk():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file part"

        file = request.files["file"]

        if file.filename == "":
            return "No selected file"

        if file:
            # Create a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
                tmp_path = tmp_file.name

            # Save the uploaded APK file to the temporary file
            file.save(tmp_path)

            # Analyze the APK using Androguard
            androguard_results = analyze_apk_with_androguard(tmp_path)

            # Analyze the APK using QARK
            qark_results = analyze_apk_with_qark(tmp_path)

            # Delete the temporary file
            os.remove(tmp_path)

            return render_template("results.html", androguard_results=androguard_results, qark_results=qark_results)

    return render_template("upload.html")

def analyze_apk_with_androguard(apk_path):
    """
    Analyze an APK using Androguard.

    Parameters:
        apk_path (str): Path to the APK file.

    Returns:
        dict: A dictionary containing analysis results.
    """
    analysis_results = {}

    try:
        # Load the APK
        a, d, dx = AnalyzeAPK(apk_path)

        # Basic APK Information
        analysis_results['Package Name'] = a.get_package()
        analysis_results['Version Name'] = a.get_androidversion_name()
        analysis_results['Version Code'] = a.get_androidversion_code()

        # Permissions
        analysis_results['Permissions'] = a.get_permissions()

        # Extract resources
        a_res = ARSCParser(a.get_android_resources())
        analysis_results['Resources'] = a_res.get_resources()

        # Extract classes
        analysis_results['Classes'] = [clazz.get_name() for clazz in d.get_classes()]

        # Dalvik Bytecode Analysis
        vm = DalvikVMFormat(a.get_dex())
        analysis = Analysis(vm)

        # Analyze Entry Points
        entry_points = analysis.get_external_classes()
        analysis_results['Entry Points'] = [entry.get_vm_class().get_name() for entry in entry_points]

    except Exception as e:
        analysis_results['Error'] = str(e)

    return analysis_results

def analyze_apk_with_qark(apk_path):
    try:
        result = subprocess.run(["qark", "--apk", apk_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        if result.returncode == 0:
            return "APK is not vulnerable."
        else:
            return f"APK is potentially vulnerable. Potential vulnerabilities:\n{output}"

    except subprocess.CalledProcessError as e:
        return f"An error occurred: {e}"

    except FileNotFoundError:
        return "QARK not found. Make sure it is installed and in your PATH."

if __name__ == "__main__":
    app.run(debug=False,host='0.0.0.0')
