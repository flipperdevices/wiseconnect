
# Wi-Fi - Paho MQTT Client Over TCP

## Table of Contents

- [Purpose/Scope](#purposescope)
- [Prerequisites/Setup Requirements](#prerequisitessetup-requirements)
  - [Hardware Requirements](#hardware-requirements)
  - [Software Requirements](#software-requirements)
  - [Setup Diagram](#setup-diagram)
- [Getting Started](#getting-started)
- [Application Build Environment](#application-build-environment)
- [Test the Application](#test-the-application)
  - [Procedure for executing the application when enabled with SSL](#procedure-for-executing-the-application-when-enabled-with-ssl)
- [Additional Information](#additional-information)
  - [Steps to set up MQTT server](#steps-to-set-up-mqtt-server)

## Purpose/Scope

This application demonstrates how to configure the device SiWx91x as an MQTT client using the Paho MQTT library and showcases the essential steps to establish a connection with the MQTT broker, subscribe to a specific topic, and publish messages on a designated topic.
SiWx91x device is configured as a Wi-Fi station and connects to an access point. After successful Wi-Fi connection, the application connects to a MQTT broker over TCP and subscribes to the topic **THERMOSTAT-DATA**. Subsequently, publishes a message **"THIS IS MQTT CLIENT DEMO FROM APPLICATION"** on the **WISECONNECT_SDK_TOPIC** topic. And, waits to receive the data published on the subscribed topic by other clients after which it unsubscribes from the topic it has subscribed to and disconnects from MQTT broker.

## Prerequisites/Setup Requirements

### Hardware Requirements  

- Windows PC
- Wireless Access Point
- Windows PC1 (for running MQTT broker)
- Windows PC2 (for running MQTT client utility - MQTT Explorer)
- SoC Mode:
  - Silicon Labs [BRD4338A, BRD4343A](https://www.silabs.com/)
  - For Soc Mode, Simplicity Studio Energy Profiler can be used for the current consumption measurement - [Simplicity Studio Energy Profiler](#using-simplicity-studio-energy-profiler-for-current-measurement).
- NCP Mode:
  - Silicon Labs [BRD4180B](https://www.silabs.com/) 
  - Host MCU Eval Kit. This example has been tested with:
    - Silicon Labs [WSTK + EFR32MG21](https://www.silabs.com/development-tools/wireless/efr32xg21-bluetooth-starter-kit)
   - Interface and Host MCU Supported
      - SPI - EFR32 
      - UART - EFR32

### Software Requirements

- Simplicity Studio

### Setup Diagram

  ![Figure: Setup Diagram for SoC mode Power Save Standby Example](resources/readme/setup_soc_ncp.png)

>**NOTE:**
>
>- The Host MCU platform (EFR32MG21) and the SiWx91x interact with each other through the SPI interface.

## Getting Started

Refer to the instructions [here](https://docs.silabs.com/wiseconnect/latest/wiseconnect-getting-started/) to:

- [Install Simplicity Studio](https://docs.silabs.com/wiseconnect/latest/wiseconnect-developers-guide-developing-for-silabs-hosts/#install-simplicity-studio)
- [Install WiSeConnect 3 extension](https://docs.silabs.com/wiseconnect/latest/wiseconnect-developers-guide-developing-for-silabs-hosts/#install-the-wi-se-connect-3-extension)
- [Connect your device to the computer](https://docs.silabs.com/wiseconnect/latest/wiseconnect-developers-guide-developing-for-silabs-hosts/#connect-si-wx91x-to-computer)
- [Upgrade your connectivity firmware ](https://docs.silabs.com/wiseconnect/latest/wiseconnect-developers-guide-developing-for-silabs-hosts/#update-si-wx91x-connectivity-firmware)
- [Create a Studio project ](https://docs.silabs.com/wiseconnect/latest/wiseconnect-developers-guide-developing-for-silabs-hosts/#create-a-project)

For details on the project folder structure, see the [WiSeConnect Examples](https://docs.silabs.com/wiseconnect/latest/wiseconnect-examples/#example-folder-structure) page.

## Application Build Environment

The application can be configured to suit your requirements and development environment. Read through the following sections and make any changes needed.

In the Project explorer pane, expand the **config** folder and open the ``sl_net_default_values.h`` file. Configure the following parameters to enable your Silicon Labs Wi-Fi device to connect to your Wi-Fi network:

- STA instance related parameters

    - DEFAULT_WIFI_CLIENT_PROFILE_SSID refers to the name with which the Wi-Fi network shall be advertised. The Si91X module is connected to it.
    
    ```c
#define DEFAULT_WIFI_CLIENT_PROFILE_SSID "YOUR_AP_SSID"      
    ```

    - DEFAULT_WIFI_CLIENT_CREDENTIAL refers to the secret key if the access point is configured in WPA-PSK/WPA2-PSK security modes.

    ```c
#define DEFAULT_WIFI_CLIENT_CREDENTIAL "YOUR_AP_PASSPHRASE" 
    ```
  
    - DEFAULT_WIFI_CLIENT_SECURITY_TYPE refers to the security type if the access point is configured in WPA/WPA2 or mixed security modes.
    ```c
#define DEFAULT_WIFI_CLIENT_SECURITY_TYPE SL_WIFI_WPA2 
    ```
> Note: 
> You can configure default region-specific regulatory information using `sl_wifi_region_db_config.h`.
 
- Other STA instance configurations can be modified if required in `default_wifi_client_profile` configuration structure.

  - MQTT_BROKER_PORT port refers to the port number on which the remote MQTT broker/server is running.

   ```c
#define SERVER_PORT 1883
   ```

  - MQTT_BROKER_IP refers remote peer IP address (Windows PC1) on which MQTT server is running.

   ```c
#define MQTT_BROKER_IP "192.168.10.1"
   ```

  - CLIENT_PORT port refers to the device MQTT client port number.

   ```c
#define CLIENT_PORT 5001
   ```
  - client.ipstack->transport_type = MQTT_TRANSPORT_TCP;

   ```c
      This sets the transport type for the MQTT client to use TCP, enabling MQTT communication over a TCP connection.
   ```
   
  - CLIENT_ID refers to the unique ID with which the MQTT client connects to MQTT broker/server.

   ```c
  int8_t clientID[] = "WISECONNECT_SDK_TOPIC";
   ```

  - PUBLISH_MESSAGE refers to message that would be published by MQTT client.

   ```c
   uint8_t publish_message[] =     "THIS IS MQTT CLIENT DEMO FROM APPLICATION";
   ```

  - QOS indicates quality of service which MQTT client uses to publish a message.

   ```c
#define QOS 0
   ```

  - KEEP_ALIVE_PERIOD client keep alive period in seconds.

   ```c
#define KEEP_ALIVE_PERIOD 100
   ```

  - MQTT_CONNECT_TIMEOUT Timeout for broker connection in milliseconds.

   ```c
#define TCP_MQTT_CONNECT_TIME_OUT 20000
   ```

  - SEND_CREDENTIALS Whether to send username and password in connect request.

   ```c
#define SEND_CREDENTIALS 0
   ```

  - USERNAME for login credentials.

   ```c
#define USERNAME "username"
   ```

  - PASSWORD for login credentials.

   ```c
#define PASSWORD "password"
   ```

**MQTT client application level memory configuration**
   ```c
//! Memory to initialize MQTT client Info structure
#define TCP_MQTT_CLIENT_INIT_BUFF_LEN 3500 
      
      //! Global buffer or memory which is used for MQTT client initialization. This is used for the MQTT client information storage.
      uint8_t tcp_mqtt_client_buffer[TCP_MQTT_CLIENT_INIT_BUFF_LEN]
   ```
## Test the Application

Refer to the instructions [here](https://docs.silabs.com/wiseconnect/latest/wiseconnect-getting-started/) to:

- Build the application.
- Flash, run, and debug the application.

- SoC mode

   ![Application prints](resources/readme/mqtt_application_prints_soc.png )

- NCP mode

   ![Application prints](resources/readme/mqtt_application_prints_ncp.png)

Follow the steps below for successful execution of the application:

- Once the SiWx91x gets connected to the MQTT broker, it will subscribe to the topic **TOPIC_TO_BE_SUBSCRIBED (Ex: "THERMOSTAT-DATA")**. You can see the client connected and subscription success information in the MQTT broker.

   **![Client connected and subscription success information](resources/readme/mqtt_connect_subscribe.png)**

- SiWx91x publishes a message which is given in **publish_message[]**. 
  (Ex: "THIS IS MQTT CLIENT DEMO FROM APPLICATION") on **PUBLISH_TOPIC** (Ex:THERMOSTAT-DATA ).

- MQTT Explorer which is running on Windows PC2 will receive the message published by the SiWx91x EVK as it subscribed to the same topic.

   **![MQTT Explorer receives the message published by the SiWx91x EVK](resources/readme/mqtt_explorer_msg.png)**

- Now to publish a message using MQTT Explorer, enter the topic name under **Publish** tab, select **raw** data format, type the data that you wish to send, and then click on **publish**. This message will be received by the SiWx91x.

    **![To publish a message using MQTT Explorer](resources/readme/mqtt_explorer_msg.png)**

- In the MQTT broker and on the terminal, you can observe the published message as the MQTT client is subscribed to that topic.

   **![In MQTT broker, user can observe the published message](resources/readme/mqtt_publish_msg_from_explorer.png)**

- SiWx91x unsubscribes to the topic that it has subscribed to after receiving the message that was published by MQTT Explorer running on Windows PC2.

- Once subscription is successful, SiWx91x disconnects from the broker.

### Procedure for executing the application when enabled with SSL

1. Install MQTT broker in Windows PC1 which is connected to the access point through LAN.

2. Update the **mosquitto.conf** file with the proper file paths, in which the certificates are available in the mosquitto.conf file.

3. Also, add **certs** folder to the mosquitto broker folder.

4. Execute the following command in MQTT server installed folder. (Ex:  C:\Program Files\mosquitto>mosquitto.exe -c mosquitto.conf -v) (Port should be 8883)

   `mosquitto.exe -c mosquitto.conf -v`  
  
   **![Run MQTTS server](resources/readme/mqtt_server.png)**

5. If you see any error - Unsupported tls_version **tlsv1**, just comment the **tls_version tlsv1** in **mosquitto.conf** file.

>**Note:**
> Multiple MQTT client instances can be created.
> If mosquitto isn't allowing external connections to the broker, add the following lines in **mosquitto.conf** file:

  ```c
  listener 1883
  allow_anonymous true
  ```


>For SSL support add this configuration in mosquitto.conf

  ```c
   listener 8883
   allow_anonymous true
#Paths to SSL / TLS certificates
   cafile   resources/certificates/ca-cert.pem
   certfile resources/certificates/server-cert.pem
   keyfile  resources/certificates/server-key.pem
   require_certificate false
 ```

> For using a different config file for mosquitto broker, use command:
  `mosquitto -v -p 1883 -c config/mosquitto.conf`
  where **config** is the sub-folder and **mosquitto.conf** is the different config file than default.

## Additional Information

### Steps to set up MQTT server

1. To run MQTT broker on port 1883 in Windows PC1, open the command prompt and go to the MQTT installed folder (Ex: C:\Program Files\mosquitto) and run the following command:

   ```c
   mosquitto.exe –p 1883 –v
   ```

   **![Run MQTT broker in Windows PC1](resources/readme/mqtt_server.png)**

2. Open MQTT Explorer in Windows PC2 and delete the existing connections, if any, and click on **Advanced** as shown in the image below.

   **![Delete the existing connections](resources/readme/mqtt_delete_connections.png)**

3. Delete the existing topic names if any. Enter the desired **TOPIC_NAME** in the topic field and click on **ADD**. The desired topic name then can be observed in the topic list. Click on **BACK** as shown in the image below.

   **![Add TOPIC NAME in topic field](resources/readme/mqtt_add_topic_name.png)**

4. Connect to MQTT broker by entering IP address and port number of Windows PC1 in HOST and PORT fields in MQTT Explorer respectively, and click on **CONNECT**. If you are running your MQTT broker on the same PC, then the following configuration is made as shown in the image below.

   **![MQTT broker Configuration](resources/readme/mqtt_connect.png)**

>**Note:**
> If we want to use IPv6 with the Paho MQTT client application, we will be using the Mosquitto command line to test the example because the MQTT Explorer application doesn't support IPv6.

> The following commands are used to test the MQTT client with IPv6 addresses using the Mosquitto command line:
>
> 1. `mosquitto_sub -h 2409:40f2:2044:d93c:f088:79d:19aa:c1c3 -p 1883 -t THERMOSTAT-DATA`
>
>    This command runs the Mosquitto client in subscriber mode.  It will connect to the MQTT broker and listen for messages published to a specific topic.
>
>    - `-h 2409:40f2:2044:d93c:f088:79d:19aa:c1c3`: Specifies the hostname or IP address of the MQTT broker to connect to. In this case, it's an IPv6 address.
>    - `-p 1883`: Specifies the network port that the MQTT broker is listening on. The default MQTT port is 1883.
>    - `-t THERMOSTAT-DATA`: Specifies the topic that the client should subscribe to. The client will receive any messages published to this topic.
>
> 2. `mosquitto_pub -h 2409:40f2:2044:d93c:f088:79d:19aa:c1c3 -p 1883 -t THERMOSTAT-DATA -m "hello"`
>
>    This command runs the Mosquitto client in publisher mode. It connects to the MQTT broker, publishes a message to a specific topic, and then automatically disconnects and closes the client.
>
>    - `-h 2409:40f2:2044:d93c:f088:79d:19aa:c1c3`: Like the `-h` option for `mosquitto_sub`, this specifies the hostname or IP address of the MQTT broker to connect to.
>    - `-p 1883`: This is the same as the `-p` option for `mosquitto_sub`, specifying the network port of the MQTT broker.
>    - `-t THERMOSTAT-DATA`: Specifies the topic that the client should publish the message to.
>    - `-m "hello"`: Specifies the message to publish. In this case, the message is the string "hello".
