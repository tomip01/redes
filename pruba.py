from scapy.all import *

cantidadDeBroadcast = 0
cantidadDeUnicast = 0
protocolosSuperiores = {}

def sumador(paquete):
    global cantidadDeBroadcast
    global cantidadDeUnicast
    # print(paquete[Ether].dst)
    if paquete[Ether].dst =='ff:ff:ff:ff:ff:ff':
        cantidadDeBroadcast += 1
    else:
        cantidadDeUnicast += 1
    
    if not paquete[Ether].type in protocolosSuperiores:
        protocolosSuperiores[paquete[Ether].type] = 1
    else:
        protocolosSuperiores[paquete[Ether].type] += 1



a = sniff(count=1, prn = sumador)

print('Cantidad de Unicast: ',cantidadDeUnicast)
print('Cantidad de Broadcast: ',cantidadDeBroadcast)
print('Cantidades por tipos de protocolos superiores: ',protocolosSuperiores)

