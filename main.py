
# ==============================================
#             CYBERGUARD
#       PHISHING URL DETECTION TOOLKIT
# ==============================================

# Import all functions from our CyberGuard package

from cyberGuard_pkg import (
    validate_url,
    check_ip_address,
    analyze_url,
    calculate_url_risk,
    detect_phishing,
    format_report
)


# ==============================================
# DISPLAY WELCOME SCREEN
# ==============================================

def welcome_screen():

    print("\n")
    print("=" * 55)
    print("              WELCOME TO CYBERGUARD")
    print("          PHISHING URL DETECTION TOOLKIT")
    print("=" * 55)

    print("CyberGuard helps identify suspicious website URLs.")
    print("It analyzes URLs and calculates their security risk.")

    print("=" * 55)


# ==============================================
# DISPLAY MAIN MENU
# ==============================================

def display_menu():

    print("\n")
    print("=" * 55)
    print("                 MAIN MENU")
    print("=" * 55)

    print("1.  Validate a Website URL")
    print("2.  Check IP Address")
    print("3.  Analyze a Website URL")
    print("4.  Calculate URL Risk Score")
    print("5.  Detect Phishing URL")
    print("6.  Generate Security Report")
    print("7.  Run Sample Test Cases")
    print("0.  Exit")

    print("=" * 55)


# ==============================================
# GET URL FROM USER
# ==============================================

def get_url():

    url = input("\nEnter Website URL: ").strip()

    return url


# ==============================================
# OPTION 1: VALIDATE URL
# ==============================================

def option_validate_url():

    print("\n---------- URL VALIDATION ----------")

    url = get_url()

    try:

        result = validate_url(url)

        if result:
            print("\nSUCCESS: The URL format is valid.")

    except ValueError as error:

        print("\nVALIDATION ERROR:", error)


# ==============================================
# OPTION 2: CHECK IP ADDRESS
# ==============================================

def option_check_ip():

    print("\n---------- IP ADDRESS CHECK ----------")

    hostname = input(
        "\nEnter an IP address or hostname: "
    ).strip()

    if not hostname:

        print("\nERROR: Input cannot be empty.")
        return

    result = check_ip_address(hostname)

    if result:

        print("\nThe entered value is a valid IP address.")

    else:

        print("\nThe entered value is not an IP address.")


# ==============================================
# OPTION 3: ANALYZE URL
# ==============================================

def option_analyze_url():

    print("\n---------- URL ANALYSIS ----------")

    url = get_url()

    try:

        result = analyze_url(url)

        print("\nURL ANALYSIS RESULT")
        print("-" * 45)

        print("Website URL:", result["url"])
        print("Hostname:", result["hostname"])

        print("\nSECURITY CHECKS")

        for check, status in result["checks"].items():

            if status:
                print(f"{check}: WARNING DETECTED")

            else:
                print(f"{check}: No warning detected")

        print("\nWARNINGS")

        if result["warnings"]:

            for warning in result["warnings"]:
                print("-", warning)

        else:

            print("No suspicious indicators detected.")

    except ValueError as error:

        print("\nERROR:", error)


# ==============================================
# OPTION 4: CALCULATE RISK SCORE
# ==============================================

def option_calculate_risk():

    print("\n---------- URL RISK CALCULATOR ----------")

    url = get_url()

    try:

        # First analyze the URL
        analysis = analyze_url(url)

        # Calculate risk using the analysis results
        risk = calculate_url_risk(
            analysis["checks"]
        )

        print("\nRISK CALCULATION RESULT")
        print("-" * 45)

        print("Website:", analysis["url"])

        print(
            "Risk Score:",
            risk["score"],
            "/100"
        )

        print("Risk Category:", risk["category"])

    except ValueError as error:

        print("\nERROR:", error)


# ==============================================
# OPTION 5: DETECT PHISHING
# ==============================================

def option_detect_phishing():

    print("\n---------- PHISHING DETECTION ----------")

    url = get_url()

    try:

        result = detect_phishing(url)

        print("\nPHISHING DETECTION RESULT")
        print("-" * 45)

        print("Website:", result["url"])
        print("Risk Score:", result["score"], "/100")
        print("Risk Level:", result["category"])

        print("\nRecommendation:")
        print(result["recommendation"])

    except ValueError as error:

        print("\nERROR:", error)


# ==============================================
# OPTION 6: GENERATE SECURITY REPORT
# ==============================================

def option_generate_report():

    print("\n---------- SECURITY REPORT ----------")

    url = get_url()

    try:

        # Detect phishing and prepare result
        result = detect_phishing(url)

        # Format the final report
        report = format_report(result)

        print(report)

    except ValueError as error:

        print("\nERROR:", error)


# ==============================================
# OPTION 7: RUN SAMPLE TEST CASES
# ==============================================

def option_test_cases():

    print("\n---------- CYBERGUARD TESTING ----------")

    test_urls = [

        "https://www.example.com",

        "http://192.168.1.10/login-verify",

        "https://bit.ly/account-update",

        "invalid-url"

    ]

    for number, url in enumerate(test_urls, start=1):

        print("\n")
        print("=" * 50)

        print("TEST CASE:", number)
        print("INPUT:", url)

        try:

            result = detect_phishing(url)

            print("RISK SCORE:", result["score"], "/100")
            print("RISK LEVEL:", result["category"])

            print("STATUS: TEST COMPLETED")

        except ValueError as error:

            print("STATUS: INVALID INPUT")
            print("ERROR:", error)

        print("=" * 50)


# ==============================================
# MAIN FUNCTION
# Controls the complete application
# ==============================================

def main():

    welcome_screen()

    while True:

        display_menu()

        choice = input(
            "\nEnter your choice (0-7): "
        ).strip()

        if choice == "1":

            option_validate_url()

        elif choice == "2":

            option_check_ip()

        elif choice == "3":

            option_analyze_url()

        elif choice == "4":

            option_calculate_risk()

        elif choice == "5":

            option_detect_phishing()

        elif choice == "6":

            option_generate_report()

        elif choice == "7":

            option_test_cases()

        elif choice == "0":

            print("\nThank you for using CYBERGUARD!")
            print("Stay Safe. Stay Secure.")
            print("=" * 55)

            break

        else:

            print("\nINVALID CHOICE!")
            print("Please select a number between 0 and 7.")


# ==============================================
# PROGRAM EXECUTION STARTS HERE
# ==============================================

if __name__ == "__main__":

    main()
