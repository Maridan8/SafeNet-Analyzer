SafeNet Analyzer Plus es una herramienta de análisis de tráfico de red que te permite capturar y analizar paquetes en tiempo real, explorar puertos, supervisar el rendimiento de la red y analizar registros de cortafuegos, todo desde una sola interfaz de línea de comandos.

## Características

- Captura de Tráfico de Red
- Análisis de Tráfico HTTP
- Escaneo de Puertos
- Supervisión de Rendimiento de Red
- Análisis de Registros del Cortafuegos
- Monitorización de Eventos de Seguridad
- Personalización
- Base de Datos y Registros: SafeNet Analyzer Plus crea una base de datos SQLite llamada captured_data.db para almacenar datos de paquetes capturados. Además, registra eventos y actividades sospechosas en archivos de registro, como logs.txt y firewall.log.

## Requisitos

Antes de utilizar SafeNet Analyzer, asegúrate de tener instalados los siguientes requisitos:

- Bibliotecas requeridas, que puedes instalar ejecutando `pip install -r requirements.txt`.

## Uso

1. Clona este repositorio en tu sistema
2. Crea un entorno virtual e instala las dependencias del proyecto.
3. Ejecuta la aplicación con Python 3.9 o superior: `python3 safenet_analyzerplus.py`.
4. (Eexcepcional) En algunas distros de linux: `sudo -E env "PATH=$PATH" python3 safenet_analyzerplus.py`

## Uso adicional:

- Si deseas analizar registros de cortafuegos, asegúrate de que los registros estén disponibles en el archivo firewall.log en el mismo directorio que el programa.
- Para explorar puertos en una red específica, modifica la variable ip_address en la función scan_network con la dirección IP y el rango de puertos deseados.
- El programa almacena datos de paquetes en una base de datos SQLite llamada captured_data.db. Puedes acceder a estos datos y realizar consultas según tus necesidades.


Recuerda personalizar y ajustar el programa según tus requisitos específicos para obtener resultados óptimos. SafeNet Analyzer Plus te permitirá capturar y analizar el tráfico de red, supervisar la seguridad de la red y tomar medidas basadas en tus necesidades de seguridad.


## Configuracion 

- Supervisa y ajusta los límites de rendimiento (opcional), el programa supervisará las estadísticas de rendimiento de la red y mostrará un mensaje de advertencia si superan ciertos límites. Puedes ajustar los límites en las variables sent_bytes_limit y received_bytes_limit según tus necesidades.

- Configura la monitorización de eventos de seguridad (opcional), el programa utiliza Pyinotify para monitorear eventos de seguridad en tiempo real, como la modificación de archivos y el acceso a archivos. Puedes personalizar los eventos que deseas monitorear y las acciones a tomar en la función monitor_security_events.
