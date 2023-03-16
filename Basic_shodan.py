#! /usr/bin/env python3

import shodan
from struct import *
from collections import *

API_KEY = 'PON AQUI LA API'
api = shodan.Shodan(API_KEY)

query = 'webcamXP'

i=0

try:
	results = api.search(query)
	#print(results)

	#Aqui se hace el parseado
	for result in results['matches']:
		print('Dispositivo %i:' %i + '--> Query: ' + query)
		print('	IP %s' %result['ip_str'])
		print('	Port: %s' %result['port'])
		print('	Organizacion: %s' %result['org'])
		print('	ISP: %s' %result['isp'])
		print('	Pais: %s' %result['location']['country_name'])
		print('	Ciudad: %s' %result['location']['city'])
		print('	Dominio: %s' %result['domains'])
		print()

		i += 1

	print('El total de dispositivos encontrados es: %i' %i)


except shodan.APIError as e:
	print("ERROR: %s" %e)
