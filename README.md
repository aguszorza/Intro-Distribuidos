# Intro-Distribuidos

### Controlador
El controller.py debe estar en pox/ext
Yo hice un hardlink para poder editar el archivo desde ambas carpetas

ln ./Desktop/Intro-Distribuidos/controller.py ./pox/ext/controller.py


## Ejecucion (terminales distintas)

./pox.py controller log.level --packet=WARN

sudo mn --custom topo.py --topo topo --mac --switch ovsk --controller remote

## Topologia dinamica
Para cambiar la cantidad de niveles o hosts clientes:

sudo mn --custom topo.py --topo topo,levels=3,hosts=10 --mac --switch ovsk --controller remote

Donde levels=x define la cantidad de niveles y hosts=y define la cantidad de clientes


