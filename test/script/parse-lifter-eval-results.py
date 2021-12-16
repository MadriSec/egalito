#!/usr/bin/python
import sys

pass_result = "PASS"
pass_key = pass_result
count_key = "COUNT"


def parse_result_entry(result_line):
    no_path = result_line.split("/")[-1]
    no_path = no_path.split("\t-\t")

    result = no_path[1].strip()

    binary = no_path[0].strip()
    binary = binary.split(".")
    subject = binary[0]
    compiler = binary[1]
    compile_setting = binary[2] + "." + binary[3] + "." + binary[4]

    return [subject, compiler, compile_setting, result]


def parse_results_file(results_file):
    test_dictionary = {count_key : 0, pass_key : 0}
    compiler_dictionary = {}
    subject_dictionary = {}

    for line in results_file:
        [subject, compiler, compile_setting, result] = parse_result_entry(line)

        # Add new dictionary entries
        if (not subject in subject_dictionary):
            subject_dictionary[subject] = {count_key : 0, pass_key : 0}

        if (not compiler in compiler_dictionary):
            compiler_dictionary[compiler] = {count_key : 0, pass_key : 0}

        if (not compile_setting in compiler_dictionary[compiler]):
            compiler_dictionary[compiler][compile_setting] = {count_key : 0, pass_key : 0}

        # Keep track of the total number of entries we've parsed for each category
        test_dictionary[count_key] += 1
        subject_dictionary[subject][count_key] += 1
        compiler_dictionary[compiler][count_key] += 1
        compiler_dictionary[compiler][compile_setting][count_key] += 1

        if (result == pass_result):
            test_dictionary[pass_key] += 1
            subject_dictionary[subject][pass_key] += 1
            compiler_dictionary[compiler][pass_key] += 1
            compiler_dictionary[compiler][compile_setting][pass_key] += 1

    return [test_dictionary, compiler_dictionary, subject_dictionary]


def get_pass_rate(summary_dict):
    return 100 * summary_dict[pass_key] / summary_dict[count_key]


def write_compiler_summary(summary_file, compiler_dictionary):
    summary_file.write("\nCOMPILER RESULTS:\n")
    for entry in compiler_dictionary:
        summary_file.write("\n" + entry + ":\n")
        pass_rate = get_pass_rate(compiler_dictionary[entry])
        summary_file.write("TOTAL % Passed: " + str(pass_rate) + "\n")
        for mode in compiler_dictionary[entry]:
            if (mode != pass_key) and (mode != count_key):
                pass_rate = get_pass_rate(compiler_dictionary[entry][mode])
                summary_file.write("\t" + mode + str(compiler_dictionary[entry][mode]) + "\t\t% Passed: " + str(pass_rate) + "\n")


def write_subject_summary(summary_file, subject_dictionary):
    summary_file.write("\nSUBJECT RESULTS:\n")
    for entry in subject_dictionary:
        summary_file.write("\n" + entry + ":\n")
        summary_file.write(str(subject_dictionary[entry]) + "\n")
        pass_rate = get_pass_rate(subject_dictionary[entry])
        summary_file.write("% Passed: " + str(pass_rate) + "\n")


def write_summary_to_file(summary_file, test_dictionary, compiler_dictionary, subject_dictionary):
    summary_file.write("SUMMARY:\n")
    summary_file.write(str(test_dictionary) + "\n")
    pass_rate = get_pass_rate(test_dictionary)
    summary_file.write("Total % Passed: " + str(pass_rate) + "\n")

    write_compiler_summary(summary_file, compiler_dictionary)
    write_subject_summary(summary_file, subject_dictionary)


def main():
    # The results file can be passed in either through the command line or through a prompt
    result_filename = ""
    if len(sys.argv) < 2:
        result_filename = input("Results file path: ")
    else:
        result_filename = sys.argv[1]

    summary_filename = result_filename + ".summary"

    with open(result_filename, 'r') as results_file:
        [test_dictionary, compiler_dictionary, subject_dictionary] = parse_results_file(results_file)

    with open(summary_filename, 'w') as summary_file:
        write_summary_to_file(summary_file, test_dictionary, compiler_dictionary, subject_dictionary)

    print("Summary written to " + summary_filename)


main()
