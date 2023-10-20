import rmqrcode
import sys


def read_input():
    """
    This function reads the input filename from the CLI input (first argument)
    and returns the content of the file.
    """
    with open(sys.argv[1], "r") as f:
        data = f.readlines()
    return data


def save_image(qr, title):
    """
    This function saves the input qr in a png file with the specified title. 
    """
    image = rmqrcode.QRImage(qr, module_size=8)
    image.save(str(title) + ".png")


def generate_codes(data):
    """
    This function iterates over input data and generates the rMQR png files.
    """
    count = 0
    dict = {}
    for elem in data:
        count += 1
        inputelem = elem.strip("\n")
        try:
            qr = rmqrcode.rMQR.fit(
                inputelem,
                fit_strategy=rmqrcode.FitStrategy.MINIMIZE_WIDTH
            )
            save_image(qr, count)
            dict[count] = inputelem
            print(str(count) + " : " + str(inputelem))
        except Exception as ex:
            print(ex)
    return dict


def generate_readme(dict):
    """
    
    """
    with open("output.md", "w+") as f:
        f.write("## " + sys.argv[1][:-4] + "\n")
        f.write("| Payload | rMQR |\n")
        f.write("| ----- | ----- |\n")
        for k,v in dict.items():
            f.write("| `" + 
                    v + 
                    "` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/" +
                    sys.argv[1][:-4] +
                    "/data/" +
                    str(k) +
                    ".png) |\n")


# -------------------- main --------------------

def main():
    data = read_input()
    dict = generate_codes(data)
    generate_readme(dict)


if __name__ == "__main__":
    main()