import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from termcolor import colored
from pyfiglet import Figlet

def get_all_forms(url):
    """Ao inserir uma `url`, ele retorna todos os formulários do conteúdo HTML"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    Esta função vai extrai todas as informações úteis sobre um `form` HTML.
    """
    details = {}
    # Obter ação do formulário (Alvo url).
    action = form.attrs.get("action").lower()
    # Obter o método do form (POST, GET, etc.).
    method = form.attrs.get("method", "get").lower()
    # Obter todos os detalhes de entrada, como tipo e nome.
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # coloque tudo no dicionário resultante.
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    """
    Envia um formulário fornecido em `form_details`
    Parâmetros:
        form_details (list): um dicionário que contém informações de formulário
        url (str): o URL original que contém esse formulário
        value (str): será substituído por todas as entradas de texto e pesquisa
    Retorna a resposta HTTP após o envio do formulário.
    """
    # Construir a URL completa (se a URL fornecido em ação for relativo).
    target_url = urljoin(url, form_details["action"])
    # Obter as entradas.
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # Substitua todos os valores de texto e pesquisa por `value`.
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # Se o nome e o valor da entrada não forem Nenhum,
            # então adicione-os aos dados de envio do formulário.
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)


def scan_xss(url):
    """
    Dado um `url`, ele imprime todos os formulários XSS vulneráveis ​​e
    retorna True se algum for vulnerável, False caso contrário.
    """
    # obtém todos os formulários da URL.
    forms = get_all_forms(url)
    print(f"[+] Detectado {len(forms)} forms injetável {url}.")
    # O payload pode ser alterado.
    js_script = "<Script>alert('xss')</scripT>"                                           
    # Valor de retorno
    is_vulnerable = False
    # Iterar sobre todas os forms.
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detectado {url}")
            print(f"[*] Detalhes do Form:")
            pprint(form_details)
            is_vulnerable = True
            #Não vai quebrar porque queremos imprimir outros formulários vulneráveis ​​disponíveis.
    return is_vulnerable

print("#" * 67)
f = Figlet(font='bulbhead')
print(colored(f.renderText("PARABELLUM"), 'white')) #banner
print("#" * 67)
f = Figlet(font='bulbhead')
print(colored(f.renderText("XSS-SCANNER"), 'white')) #banner
print("#" * 67)
f = Figlet(font='digital')
print(colored(f.renderText("by wtechsec"), 'white')) #banner
print("#" * 67)

url = input("Insira a URL: ")
scan_row = url.split(" ")

if len(scan_row)!=2:
    print(scan_xss(url))


