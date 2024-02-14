# SL MUTEX EXAMPLE

## Table of Contents

- [Purpose/Scope](#purposescope)
- [Prerequisites/Setup Requirements](#prerequisitessetup-requirements)
  - [Hardware Requirements](#hardware-requirements)
  - [Software Requirements](#software-requirements)
  - [Setup Diagram](#setup-diagram)
- [Getting Started](#getting-started)
- [Application Build Environment](#application-build-environment)
- [Test the Application](#test-the-application)

## Purpose/Scope

- The purpose of this application is to demonstrate the use of CMSIS-RTOS concepts embedded with multiple peripherals. The following concepts are demonstrated:
  - Mutex
- This application contains an example code to demonstrate the GPIO/LED toggle functionality
- This example creates two threads for driving the same LED (which implies common resource)
- These threads run in parallel but are synchronized by Mutex for driving the LED

## Overview
 - One of the threads is intended only for turning on the LED, and other for turning it off
 - Each thread waits for acquiring the same Mutex. As soon as one acquires, it waits until current timeout is expired (keeping the LED state unchanged), then drives the LED (either on/off which the thread is intended to do)

## Prerequisites/Setup Requirements

### Hardware Requirements

- Windows PC
- Silicon Labs Si917 Evaluation Kit [WPK(BRD4002) + BRD4338A]

### Software Requirements

- Simplicity Studio

### Setup Diagram

> ![Figure: Introduction](resources/readme/setupdiagram.png)

## Getting Started

Refer to the instructions [here](https://docs.silabs.com/wiseconnect/latest/wiseconnect-getting-started/) to:

- Install Studio and WiSeConnect 3 extension
- Connect your device to the computer
- Upgrade your connectivity firmware
- Create a Studio project

## Application Build Environment

- Configure the following parameter in blinky.c file, update/modify following macro if required.

  ```C
    #define TOGGLE_DELAY_MS 500//  configured for 500 ms   
  ```   

## Test the Application

1. Sets the board state of LED0 to ON and OFF for configured blink rate and then device goes to sleep.
2. LED0 should blink on WSTK/WPK base board.

  > **Note!**
  >
  > LED0 OFF, LED0 ON, device sleep will be a continous process.
 