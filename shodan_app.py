#usr/bin/env python3

import os, platform
import shodan, ast
import time

from datetime import datetime
#from struct import *
#from collections import *

https_head = "https:" + r"\\"

def cleanShell():
	os.system('cls||clear')



def app_interface():
	cond = False

	while(cond == False):
		print("Bienvenido a la interfaz de consultas IoT basada en Shodan, escoja una opcion:")
		print("	1)Realizar una nueva consulta en Shodan")
		print("	2)Analizar resultados de una consulta anterior")
		print("	0)Salir de la aplicacion")
		print()
		num=input("Introduzca el entero de la accion a ejecutar: ")

		match num:
			case '0':
				cond = True
				print("Saliendo de la aplicacion...")

			case '1':
				shodan_query()

			case '2':
				analyzer()

			case _:
				print("Numero invalido")
				print()


def check_api_key():
	filename = "API_key.key"

	if os.path.exists(filename):
		print("Se ha encontrado un fichero de API key")
		with open(filename, 'r') as file:
			API_KEY = file.read()

	else:
		print("No se ha encontrado el fichero, creando uno nuevo...")
		with open(filename, 'w') as file:
			API_KEY = input("Introduzca la API key que se utilizara: ")
			file.write(API_KEY)

	cleanShell()
	print("Se utilizara la API key: " + API_KEY)

	#Se pregunta al usuario si desea proceder con esta API key o modificarla
	test = False

	while(test == False):
		OK = input("¿Desea proceder con esta API key? [Y/N]: ")

		if(OK == 'N'):
			with open(filename, 'w') as file:
				API_KEY = input("Introduzca la nueva API key: ")
				file.write(API_KEY)
			print("Se utilizara la API key: " + API_KEY)

		elif(OK == 'Y'):
			test = True

		else:
			cleanShell()
			print("Respuesta invalida, vuelva a introducir una respuesta...")

	cleanShell()
	return API_KEY


def shodan_query():
	cond = True
	cleanShell()

   #Primero se comprobara si existe un fichero api_key:
	API_KEY = check_api_key()

   #Ahora se solicita la query principal
	m_search = input("Introduzca la busqueda principal: ")

	query = m_search

	cnd = ''
	while(cnd != 'N'):
		cnd = input("¿Desea aplicar mas filtros [Y/N]?: ")
		match cnd:
			case 'N':
				cleanShell()
				print("Lanzando la query a Shodan, por favor espere...")
				print()

			case 'Y':
				print("1)Aplicar filtro por organizacion")
				print("2)Aplicar filtro por pais")
				print("3)Aplicar filtro por ciudad")
				sel = input("Introduzca el numero del filtro que desea aplicar: ")

				match sel:
					case '1':
						organ = input("Introducza la string de la organizacion: ")
						query = query + " org:" + "\"" + organ + "\""
					case '2':
						c_code = input("Introduzca el codigo de pais: ")
						query = query + " country:" + "\"" + c_code + "\""
					case '3':
						ciudad = input("Introduzca el nombre de la ciudad: ")
						query = query + " city:" + "\"" + ciudad + "\""
					case _:
						print("El caso indicado no esta reconocido")

			case _:
				cleanShell()
				print("Error: Argumento no valido")

	print("La query que se lanzara sera: " + query)
	print()

	print("Conectando con Shodan mediante la API key: " + API_KEY)
	shodan_request(API_KEY, query)


def check_description(cve):
	vuln_des = []

	if(len(cve["matches"]) > 0):
		for a in cve["matches"]:
			dict = {}
			if(len(a["description"]) > 0):
				dict[str(a["cve"])] = a["description"]
				vuln_des.append(dict)
	return vuln_des


def shodan_request(key, qry):

	try:

	#Se ejecuta la query basica
		api = shodan.Shodan(key)
		results = api.search(qry)

		log_date = str(datetime.now())

		name = "query_result-" + log_date +".data"
		with open(name, 'w') as file:
			file.write(str(results))

	#Al finalizar la query basica se lanza la query de vulnerabilidades tras 2 segundos,
	#estos dos segundos son para evitar que la API tenga comportamientos anomalos.
		time.sleep(2)

		dict_device = {}

		device = []
		IP_addr = []
		ports_ip = []
		tags = []
		country_ip = []
		city_ip = []
		isp_ip = []
		gps = []
		vuln_date = []
		vuln_name = []
		vuln_description = []

		j = 1


		for elemento in results["matches"]:

			hostdata = api.host(elemento["ip_str"])

			device.append(j)
			IP_addr.append(hostdata["ip_str"])
			ports_ip.append(hostdata["ports"])
			tags.append(hostdata["tags"])
			country_ip.append(hostdata["country_name"])
			city_ip.append(hostdata["city"])
			isp_ip.append(hostdata["isp"])

			GPS = {}
			GPS["latitude"] = hostdata["latitude"]
			GPS["longitude"] = hostdata["longitude"]
			gps.append(GPS)

			#Con la informacion anterior como base lo que sigue ya es vulnerabilidades
			vuln_date.append(hostdata["last_update"])
			j += 1

			if("vulns" in hostdata and len(hostdata["vulns"])):
				vuln_name.append(hostdata["vulns"])
				for vuln in hostdata["vulns"]:
					if vuln.startswith("!"):
						continue

					try:
						exploit_db = api.exploits.search(vuln)
						vuln_description = check_description(exploit_db)

					except shodan.APIError as e:
						print("Error en query CVE: %s" %e)
			else:
				vuln_name.append("")

		dict_device["device"] = device
		dict_device["IP"] = IP_addr
		dict_device["ports"] = ports_ip
		dict_device["country"] = country_ip
		dict_device["ISP"] = isp_ip
		dict_device["GPS"] = gps
		dict_device["updated"] = vuln_date
		dict_device["CVE"] = vuln_name
		dict_device["CVE_description"] = vuln_description

		vuln_log_date = str(datetime.now())
		filename = "query_vuln-" + vuln_log_date + ".data"

		with open(filename, 'w') as file:
			file.write(str(dict_device))

	except shodan.APIError as e:
		print("Error durante comunicacion: " "\"%s\"" %e)


def analyzer():
	files = os.listdir()
	elementos = []
	salida = False

	cleanShell()

	while(salida == False):
		print("Usted esta dentro de la funcion analizadora de la app, seleccione una opcion: ")
		print("	1)Hacer dump de IPs y puertos")
		print("	2)Analisis de vulnerabilidades")
		print("	0)Salir del analizador")

		print()
		n = input("Numero de la tarea seleccionada: ")

		match n:
			case "0":
				salida = True
				cleanShell()
			case "1":
				ctr = 1
				for i in files:
					if("query_result" in i):
						print(str(ctr) + ")" + i)
						elementos.append(i)
						ctr += 1
				if(ctr == 1):
					print("ERROR: No se detectan ficheros, ejecute primero un analisis en Shodan")
					print("Saliendo al menu principal de la aplicacion")
					print()
					salida = True
				else:
					indice = input("Introduce el numero del elemento a analizar: ")
					indice = int(indice) - 1
					cleanShell()
					chng_file = False

					while(chng_file == False):
						rp = input("Se ha seleccionado " + str(elementos[indice]) + ". ¿Desea proceder [Y/N]? ")

						match rp:
							case "Y":
								cleanShell()
								dump_IPs_ports(elementos[indice])
								chng_file = True
							case "N":
								chng_file = True
							case _:
								print("ERROR: Caracter introducido invalido")

			case "2":
				ctr = 1
				for i in files:
					if("query_vuln" in i):
						print(str(ctr) + ")" + i)
						elementos.append(i)
						ctr += 1
				if(ctr == 1):
					print("ERROR: No se detectan ficheros, ejecute primero un analisis de vulnerabilidades en Shodan")
					print("Saliendo al menu principal de la aplicacion")
					print()
					salida = True
				else:
					indice = input("Introduce el numero del elemento a analizar: ")
					indice = int(indice) - 1
					cleanShell()
					chng_file = False

					while(chng_file == False):
						rp = input("Se ha seleccionado " + str(elementos[indice]) + ". ¿Desea proceder [Y/N]? ")

						match rp:
							case "Y":
								cleanShell()
								vuln_analysis(elementos[indice])
								chng_file = True
							case "N":
								chng_file = True
							case _:
								print("ERROR: Caracter introducido invalido")

			case "_":
				print("ERROR: Numero invalido")
				print()


def dump_IPs_ports(f_name):
	IP_file = "IPs_ports_analysis--" + f_name[13::]
	i = 0

	with open(f_name, 'r') as file:
		text = file.read()
		text = ast.literal_eval(text)

	with open(IP_file, 'w') as file:
		for elemento in text['matches']:
			file.write("Dispositivo "+ str(i+1) + ":\n")
			file.write("	Identified OS: %s" %elemento["os"] + "\n")
			file.write("	ISP: %s" %elemento["isp"] + "\n")
			file.write("	IP: %s" %elemento["ip_str"] + "\n")
			file.write("	Port: %s" %elemento["port"] + "\n")
			file.write("	URL: " + https_head  + str(elemento["ip_str"]) + ":" + str(elemento["port"])  + "\n")
			file.write("	Position -> Latitude: %s" %elemento["location"]["latitude"] + "; Longitude: %s" %elemento["location"]["longitude"] + "\n")
			file.write("\n")
			i += 1

		file.write("\n")
		file.write("Se han encontrado %i dispositivos" %i + "\n")
		file.write("\n")

	print("Se ha creado el fichero: " + IP_file)
	quit = False

	while(quit == False):
		resp = input("¿Desea ver el contenido del fichero? [Y/N]: ")
		match resp:
			case 'Y':
				with open(IP_file, 'r') as file:
					print(file.read())

				q_in = ''
				while(q_in != 'q'):
					q_in = input("Introduzca [q] para salir del modo visualizacion: ")

					if(q_in != 'q'):
						print("ERROR: Caracter no reconocido, [q] para salir...")
					else:
						quit = True
			case 'N':
				quit = True

			case _:
				print("ERROR: Caracter no reconocido")

	print()
	cleanShell()



def vuln_analysis(f_name):
	lista = []
	lista_ord = []
	dispositivos = []

	with open(f_name, 'r') as file:
		text = file.read()
		text = ast.literal_eval(text)

	n_elementos = len(text["device"])
	claves = text.keys()

	for i in claves:
		lista.append(text[i])

	for j in range(0, n_elementos):
		for i in range(0, len(claves) - 1):
			lista_ord.append(lista[i][j])
		dispositivos.append(lista_ord)
		lista_ord = []

    #Con el formato hecho ahora se interactua con el usuario
	c = False

	while(c == False):
		n = int(input("Introduzca un numero entero rango[1, " + str(n_elementos) + "] para mostrar la informacion del dispositivo: "))
		cleanShell()

		if((n > 0) and (n <= (n_elementos))):
			n = n - 1
			for i in range(0, len(claves) - 1):
				match i:
					case 0:
						print("	Dispositivo " + str(dispositivos[n][i]) + ":")
					case 1:
						print("		IP: " + str(dispositivos[n][i]))
					case 2:
						print("		Puertos abiertos: " + str(dispositivos[n][i]))
					case 3:
						print("		Ubicacion por pais: " + str(dispositivos[n][i]))
					case 4:
						print("		ISP: " + str(dispositivos[n][i]))
					case 5:
						print("		Posicion GPS: " + str(dispositivos[n][i]))
					case 6:
						print("		Ultima actualizacion: " + str(dispositivos[n][i]))
					case 7:
						print("		CVE identificadas: " + str(dispositivos[n][i]))
					case _:
						pass

			print()
			print()
			rst = False

			while(rst == False):
				resp = input("¿Desea realizar una nueva consulta [Y/N]? ")
				match resp:
					case "Y":
						rst = True
						cleanShell()
					case "N":
						rst = True
						c = True
						cleanShell()
					case "_":
						cleanShell()
						print("ERROR: Caracter invalido")
						print()

		else:
			print("ERROR: El numero introducido es invalido")
			print()
			print()


def __main__():
	cleanShell()
	app_interface()


#Llamada al elemento principal
__main__()
