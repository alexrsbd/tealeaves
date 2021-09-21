#Name: Sage Tea Leaves
#Author: Alex Sullivan
#Version: 1.1
#Usage: python3 tealeaves.py sage_says.json

import json
import sys
import logging
import math

logging.basicConfig(format='%(message)s')

log = logging.getLogger()
log.setLevel(logging.DEBUG)

handler = logging.FileHandler("tealeaves.log")

log.addHandler(handler)

lnbreak = "*-----------------------------------------------*"

def banner():
    log.debug("      ______________________________")
    log.debug("    / \                             \ ")
    log.debug("   |   |        Sage Tea Leaves      |")
    log.debug("    \_ |   __________________________|___")
    log.debug("       |  /                            / ")
    log.debug("       \_/____________________________/ ")

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])

def loadSage(path):
    try:
        with open(path) as f:
            sageJson = json.load(f)
            return sageJson
    except PermissionError:
        log.debug("Permission error trying to open: \'" + sys.argv[1] + "\'")
        return 1

def checkSage(sage):
    # SAGE DETAILS
    try:
        log.debug("              Sage Version: " + str(sage["sage_version"]))
        log.debug(lnbreak)
    except TypeError:
        log.debug("Could not get Sage version. Is \'" + sys.argv[1] + "\' a sage_says.json?")
        return 1
    except KeyError:
        log.debug("Could not get Sage version. Is \'" + sys.argv[1] + "\' a sage_says.json?")
        return 1
    except IOError:
        log.debug("Could not open " + sys.argv[1])
    # BLACK DUCK DETAILS
    try:
        log.debug("              Black Duck Details")
        log.debug(lnbreak)
        log.debug("Black Duck URL: " + str(sage["hub_url"]))
        log.debug("Black Duck Version: " + str(sage["hub_version"]["version"]))
        log.debug("Time of analysis: " + str(sage["time_of_analysis"]))
        log.debug("Number of policies: " + str(len(sage["policies"])))
        log.debug("Number of projects: " + str(sage["total_projects"]))
        log.debug("Number of project versions: " + str(sage["total_versions"]))
        log.debug("Number of scans: " + str(sage["total_scans"]))
        log.debug("Number of bom scans: " + str(sage["number_bom_scans"]))
        log.debug("Number of signature scans: " + str(sage["number_signature_scans"]))
        log.debug("Total scan size: " + str(convert_size(sage["total_scan_size"])))
        log.debug(lnbreak)
        return 0
    except IOError:
        log.debug("An error occurred trying to get Black Duck details from: " + str(sys.argv[1]))
        log.debug("Unexpected error:", sys.exc_info()[0])
        return 1

def tooManyVersions(sage):
    log.debug("        Projects With Too Many Versions\n" + lnbreak)
    try:
        log.debug("Number of projects with too many versions: " + str(len(sage["projects_with_too_many_versions"])))
    except IOError:
        log.debug("An error occurred trying to get \'projects with too many versions details\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error:", sys.exc_info()[0])
        return 1

    log.debug("The recommended max number of versions per project is 15.\n\nYou should review these versions and remove extraneous ones, and their scans, to reclaim space and reduce clutter.\nTypically, there should be one version per development branch, and one version per release.\nWhen new vulnerabilities are published you want to be able to quickly identify which projects are affected and take action.\nKeeping a large number of un-released versions in the system will make that difficult.\nAccruing a large number of versions per project can lead to serious performance degradation.\nLook at https://github.com/blackducksoftware/hub-rest-api-python/tree/master/examples for python examples for finding/deleting/removing versions and their scans.")
    log.debug(lnbreak)
    try:
        i = 0
        tmv = []
        while i < len(sage["projects_with_too_many_versions"]):
            tmv.append([str(sage["projects_with_too_many_versions"][i]["name"]), int(sage["projects_with_too_many_versions"][i]["num_versions"])])
            i += 1
        i = 0
        tmv.sort(key=lambda r:r[1], reverse=True)
        if len(tmv) < 20:
            while i < len(tmv):
                log.debug("Project: \'" + tmv[i][0] + "\' | Version count: \'" + str(tmv[i][1]) + "\'")
                i += 1
        else:
            tmvlog = open("tealeaves_too_many_versions.log", "a")
            log.debug("Due to an abundant number of projects with too many versions, full results will be written to \'too_many_versions.log\'.")
            while i < len(tmv):
                if i < 10:
                    log.debug("Project: \'" + tmv[i][0] + "\' | Version count: \'" + str(tmv[i][1]) + "\'")
                tmvlog.write("Project: \'" + tmv[i][0] + "\' | Version count: \'" + str(tmv[i][1]) + "\'\n")
                i += 1
        log.debug(lnbreak)
        return 0
    except IOError:
        log.debug("An error occurred trying to get \'projects with too many versions details\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error:", sys.exc_info()[0])
        return 1

def tooManyScans(sage):
    log.debug("         Versions With Too Many Scans\n" + lnbreak)
    try:
        log.debug("Number of versions with too many scans: " + str(len(sage["versions_with_too_many_scans"])))
    except IOError:
        log.debug("An error occurred trying to get \'versions with too many scans details\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error:", sys.exc_info()[0])
        return 1

    log.debug(
        "The maximum recommended number of scans per project version is 10.\n\nReview the scans to make sure there are not redundant scans all mapped to this project version.\nLook for scans with similar names or sizes.\nIf redundant scans are found, you should delete them and update the scanning setup to use --detect.code.location.name with Synopsys detect to override scan names and delete redundant scans.")
    log.debug(lnbreak)
    try:
        i = 0
        tms = []
        while i < len(sage["versions_with_too_many_scans"]):
            tms.append([str(sage["versions_with_too_many_scans"][i]["project_name"]), str(sage["versions_with_too_many_scans"][i]["versionName"]), int(sage["versions_with_too_many_scans"][i]["num_scans"])])
            i += 1
        i = 0
        tms.sort(key=lambda r:r[2], reverse=True)
        while i < len(tms):
            log.debug("Project: \'" + str(tms[i][0]) + "\' | Version: \'" + tms[i][1] + "\' | Scan count: " + str(tms[i][2]))
            i += 1
        log.debug(lnbreak)
        return 0
    except IOError:
        log.debug("An error occurred trying to get \'versions with too many scans details\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error:", sys.exc_info()[0])
        return 1

def zeroScans(sage):
    log.debug("          Versions With Zero Scans\n" + lnbreak)
    try:
        log.debug("Number of versions with zero scans: " + str(len(sage["versions_with_zero_scans"])))
    except IOError:
        log.debug("An error occurred trying to get details on \'zero scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error:", sys.exc_info()[0])
        return 1
    log.debug("You should review any project versions with zero scans and delete it if it is not being used.\nOne exception is if someone created this project-version to populate with components manually, i.e. no scans are mapped to it, but the BOM inside this version is populated by manually adding components to it.")
    log.debug(lnbreak)
    i = 0
    try:
        if len(sage["versions_with_zero_scans"]) < 200:
            while i < len(sage["versions_with_zero_scans"]):
                log.debug("Project \'" + str(sage["versions_with_zero_scans"][i]["project_name"]) + "\' | Version \'" + str(sage["versions_with_zero_scans"][i]["versionName"]) + "\'")
                i += 1
        else:
            log.debug("Due to the abundant number of versions with zero scans, the list of violating versions will be written to tealeaves_zero_scans.log")
            zslog = open(str("tealeaves_versions_zero_scans.log"), "a")
            while i < len(sage["versions_with_zero_scans"]):
                zslog.write("Project \'" + str(sage["versions_with_zero_scans"][i]["project_name"]) + "\' | Version \'" + str(sage["versions_with_zero_scans"][i]["versionName"]) + "\'\n")
                i += 1
            zslog.close()
        log.debug(lnbreak)
        return 0
    except IOError:
        log.debug("An error occurred trying to get details on \'zero scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error: ", sys.exc_info()[0])
        return 1

#HIGH FREQUENCY SCANS - currently disabled because of a sage isn't taking scanType into account, causing inaccurate numbers
def highFrequency(sage):
    log.debug("          High Frequency Scans\n" + lnbreak)
    log.debug(lnbreak)
    try:
        log.debug("Total number of high frequency scans: " + str(len(sage["high_frequency_scans"])))
    except IOError:
        log.debug("An error occurred while trying to get details on \'high frequency scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error: ", sys.exc_info()[0])
        return 1
    log.debug("High frequency scans are code locations that have two or more scans (out of 2) that were run within 24 hours of each other which may indicate a scan that is being run too often. Consider reducing the frequency to once per day.")
    log.debug("Processing scans consumes Black Duck resources. Unnecessarily scanning a project over and over again will not yield new results if your open source did not change.")
    log.debug("Please consider how frequently you are scanning your project, and potentially scan it on a daily schedule instead of per build.")
    log.debug("\nList of High Frequency Scans")
    log.debug(lnbreak)
    i = 0
    try:
        while i < len(sage["high_frequency_scans"]):
            if len(sage["high_frequency_scans"][i]["scan_summaries"]) > 3:
                log.debug("Scan \'" + str(sage["high_frequency_scans"][i]["name"]) + "\' was scanned " + str(int(len(sage["high_frequency_scans"][i]["scan_summaries"]))) + " within 24 hours.")
            i += 1
        log.debug(lnbreak)
        return 0
    except IOError:
        log.debug("An error occurred while trying to get details on \'high frequency scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error: ", sys.exc_info()[0])
        return 1

def unmappedScans(sage):
    log.debug("          Unmapped Scans\n" + lnbreak)

    try:
        log.debug("Number of unmapped scans: " + str(len(sage["unmapped_scans"])))
    except IOError:
        log.debug("An error occurred while trying to get details on \'unmapped scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error: ", sys.exc_info()[0])
        return 1
    log.debug("Unmapped scans should either be mapped to something or deleted to reclaim space and reduce clutter. Clutter may impact system performance.\nLook at https://github.com/blackducksoftware/hub-rest-api-python/tree/master/examples for python examples for finding/deleting/removing unmapped scans.")
    log.debug("\nPay attention to your scan names. Having many scans with similar scan names can be an indication of redundant scanning.\nAvoid using build numbers in your scan names to avoid creating an overwhelming amount of redundant scans.\nRedundant scans can cause performance degradation by overwhelming the system with scans.")
    log.debug("Instead, please consider overwriting your previous scans by reusing the same scan name, instead of saving redundant copies under unique names.")
    log.debug("\nPlease consider consulting https://community.synopsys.com/s/article/Black-Duck-Scanning-Best-Practices to ensure that you are naming your scans optimally.")
    log.debug("You can also consider refining your usage of the following Detect flags")
    log.debug("--detect.code.location.name\n--detect.project.codelocation.prefix\n--detect.project.codelocation.suffix")
    i = 0
    unmappedSize = 0
    try:
        while i < len(sage["unmapped_scans"]):
            unmappedSize += int(sage["unmapped_scans"][i]["scanSize"])
            i += 1
    except IOError:
        log.debug("An error occurred while trying to get details on \'unmapped scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error: ", sys.exc_info()[0])
        return 1
    log.debug(lnbreak)
    log.debug("          " + str(convert_size(unmappedSize)) + " of unmapped scans")
    log.debug(lnbreak)
    log.debug("          List of Unmapped Scans")
    log.debug(lnbreak)
    i = 0
    try:
        if len(sage["unmapped_scans"]) < 200:
            while i < len(sage["unmapped_scans"]):
                log.debug(str(sage["unmapped_scans"][i]["name"]))
                i += 1
        else:
            log.debug("Due to the abundant number of unmapped scans, the list of scans will be written to tealeaves_unmapped_scans.log")
            umlog = open(str("tealeaves_unmapped_scans.log"), "a")
            while i < len(sage["unmapped_scans"]):
                umlog.write(str(sage["unmapped_scans"][i]["name"]+"\n"))
                i += 1
            umlog.close()
    except IOError:
        log.debug("An error occurred while trying to get details on \'unmapped scans\' from: " + str(sys.argv[1]))
        log.debug("Unexpected error: ", sys.exc_info()[0])
        return 1
    return 0

def teaLeaves(sage):
    log.debug("\nReading your system's tea leaves...")
    log.debug(lnbreak)
    if checkSage(sage) != 0:
        return 1
    tooManyVersions(sage)
    tooManyScans(sage)
    zeroScans(sage)
    #highFrequency(sage) #Disabled because of a sage bug that isn't taking scanType into account, causing inaccurate numbers
    unmappedScans(sage)


if __name__ == '__main__':
    banner()
    if loadSage(sys.argv[1]) == 1:
        exit(1)
    else:
        sageSays = loadSage(sys.argv[1])
        if teaLeaves(sageSays) != 0:
            exit(1)
