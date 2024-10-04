# Android-Part-1---Static-analysis
Android Penetration Testing - Part 1 - STATIC ANALYSIS

Static analysis in Android refers to a method of analyzing the source code or compiled code of an Android application without actually executing it. This approach involves examining the code to identify potential issues, vulnerabilities, and code smells, as well as checking for compliance with coding standards and best practices1.

Here are some key points about static analysis in the context of Android:
Purpose of Static Analysis:
Early Detection: Static analysis helps identify security vulnerabilities and other issues early in the development process, allowing developers to address them before deployment.

Code Quality: It also assists in maintaining code quality by highlighting potential problems, such as unused variables, incorrect function calls, or inefficient code.
Compliance: Developers can ensure compliance with coding standards and best practices through static analysis.
Static Analysis Process:
Source Code Examination: Static analysis inspects the source code without executing it, covering all possible execution paths.

Security Vulnerabilities: It helps identify potential security vulnerabilities, coding errors, and compliance issues.

Popular Tools for Static Analysis in Android:
Lint: Built into Android Studio, Lint checks for common coding issues and provides suggestions for improvement.

FindBugs: Detects bugs and potential vulnerabilities in Java code.

PMD: Analyzes code for bad practices and coding style violations.

Checkstyle: Enforces coding standards and conventions.

SpotBugs: An improved version of FindBugs.

Dex2jar is a powerful set of tools designed to work with Android .dex and Java .class files. Let’s explore its components:

dex-reader/writer: This tool allows you to read and write the Dalvik Executable (.dex) files. It provides a lightweight API similar to ASM.

d2j-dex2jar: Convert .dex files to .class files (zipped as JAR). It’s a handy utility for decompiling Android applications.

smali/baksmali: These tools disassemble .dex files into Smali files and assemble .dex files from Smali files. While they have the same syntax as other Smali tools, they offer additional support for escaping in type descriptions (e.g., Lcom/dex2jar\t\u1234;).

MobSF😎

I will suggest to first take you APK file and paste over mobsf.live

Mobsf is best tool to understands to android pentest and basic of android security vulnerabilities.

Mobile Security Framework (MobSF) is a powerful security research platform designed for mobile applications in Android, iOS, and Windows Mobile. It serves various purposes, including mobile application security, penetration testing, malware analysis, and privacy assessment

JADX is a powerful tool for decompiling Android DEX files (Dalvik Executable) into Java source code. It allows you to analyze and understand the inner workings of Android applications. Let’s explore its features:

Command-Line Version (jadx):
Decompiles DEX files to Java code from APKs, DEX files, JARs, classes, Smali files, ZIP files, AARs, and more.
Decodes AndroidManifest.xml and other resources from resources.arsc.
Includes a deobfuscator.
Provides various options for customization.
Note that jadx may not decompile 100% of the code due to limitations.
2. Graphical User Interface (jadx-gui):

Offers a user-friendly interface for viewing decompiled code.
Features include:
Highlighted syntax.
Jump to declaration.
Find usage.
Full-text search.
Smali debugger (check the wiki page for setup and usage).
You can download the latest unstable build from the GitHub releases.
Usage:

After downloading, unpack the ZIP file.

Navigate to the bin directory.

Run:

jadx for the command-line version.

jadx-gui for the graphical version.

Ensure you have Java 11 or later (64-bit version) installed.

Jarsigner method after decompiling apk files

After decompiling APK files, you can use the jarsigner tool to sign and verify Java Archive (JAR) files. Let’s break down its usage:

Signing JAR Files:
Purpose: Signing JAR files ensures their authenticity, integrity, and non-repudiation.
2. How It Works:

A digital signature is generated using the private key associated with an entity (person, company, etc.).
The signature is computed from the data being signed (the JAR file) and the private key.
The signed JAR file contains this digital signature.
Command:
jarsigner [options] jar-file alias
jar-file: The JAR file to be signed.
alias: The keystore alias (defined in the keystore) used for signing.
Example:
jarsigner -keystore mykeystore.jks -storepass mypassword myapp.jar myalias
Vulnerabilities which needs to check during static analysis.

Excessive Permissions:

Android apps sometimes request more permissions than necessary, potentially exposing sensitive user data or device functionality.

Mitigation: Review and minimize the requested permissions to only what is essential for the app’s functionality.

Hardcoded Credentials:

Developers occasionally embed credentials (such as API keys, passwords, or tokens) directly in the code.

Mitigation: Avoid hardcoding credentials; use secure storage mechanisms or environment variables.

Weak Cryptographic Functions:

Weak encryption algorithms or improper use of cryptographic functions can lead to data leaks or unauthorized access.

Mitigation: Use strong encryption algorithms and follow best practices for key management.

Workflow Bypass:

Flaws in the app’s logic may allow attackers to bypass authentication or authorization checks.

Mitigation: Thoroughly test the app’s workflows to ensure proper access controls.

Hidden Features:

Apps may contain hidden features or backdoors unintentionally left in the code.

Mitigation: Regularly review the codebase for any unintended functionality.

Improper Log Management:

Inadequate logging practices can leak sensitive information or expose vulnerabilities.

Mitigation: Implement proper logging, avoid logging sensitive data, and secure log files.

Insecure Storage:

Storing sensitive data (such as passwords or tokens) insecurely (e.g., in plain text or weakly encrypted) poses a risk.

Mitigation: Use secure storage mechanisms (e.g., Android Keystore) for sensitive data.

improper Input Validation:

Lack of proper input validation can lead to security vulnerabilities, such as SQL injection or buffer overflows.

Mitigation: Validate user input rigorously to prevent injection attacks.

Code Injection Attacks:

Insecure dynamic code execution (e.g., using eval()) can allow attackers to inject malicious code.

Mitigation: Avoid dynamic code execution and sanitize inputs.

Adherence to Coding Standards:

Deviations from coding standards can introduce vulnerabilities.

Mitigation: Follow established coding guidelines and best practices.

AndroidManifest.xml file plays a crucial role. Let’s explore some common vulnerabilities and how to address them:

Exposed Components:
Issue: Components (such as activities, services, or broadcast receivers) declared in the manifest file may be exposed to other apps unintentionally.
Mitigation:
Set the android:exported attribute to false for components that should not be accessible externally.
Define permissions for exported components using the android:permission attribute.
If no permissions are needed, set android:permission="" to explicitly indicate no permissions are required.
2. Debuggable Mode:

Issue: If android:debuggable="true" is set in the manifest, it allows running commands on behalf of the app via ADB (Android Debug Bridge).
Mitigation:
Ensure that debuggable mode is disabled (android:debuggable="false") in production builds.
Use build flavors or Gradle properties to control debuggable mode during development and production2.
3. Improper Permissions:

Issue: Components may lack proper permissions, leading to unauthorized access.
Mitigation:
Define custom permissions using <permission> tags in the manifest.
Associate these permissions with components using the android:permission attribute.
Ensure that components requiring specific permissions are properly protected1.
4. WebView Vulnerabilities:

Issue: WebViews embedded in the app may have security flaws.
Mitigation:
Inspect the manifest for WebView components.
Review the WebView configuration (e.g., JavaScript enabled, insecure content loading).
Regularly update WebView libraries to address known vulnerabilities3.
5. Network Security Configuration:

Issue: Inadequate network security configuration can lead to insecure communication.
Mitigation:
Review the network_security_config.xml file (if present).
Specify secure domains, enforce HTTPS, and restrict cleartext traffic.
Use the android:networkSecurityConfig attribute in the manifest4.
Android DEX files (Dalvik Executable) and how they can impact the security of Android applications:

Janus Vulnerability (CVE-2017–13156):
Description: The Janus vulnerability allows attackers to inject a DEX file into an APK file without affecting the app’s signatures. Essentially, it modifies the code within applications without altering their signatures.
Exploitation:
An attacker can prepend a malicious DEX file to a legitimate APK file.
The Android runtime accepts the modified APK as a valid update of the original app.
However, the Dalvik VM loads the code from the injected DEX file.
Consequences:
Attackers can mislead the update process and install unverified code with powerful permissions on users’ devices.
For example, an attacker could replace a trusted system app with a modified update to abuse its permissions.
Mitigation:
Ensure proper signature verification during app updates.
Be cautious when handling dual DEX/APK files1.
Other Vulnerabilities:
Exposed Components: Improperly configured components (activities, services, broadcast receivers) in the AndroidManifest.xml can lead to unauthorized access.
Debuggable Mode: If android:debuggable="true" is set, it allows running commands via ADB, potentially exposing sensitive data.
Weak Cryptography: Insecure use of cryptographic functions can lead to data leaks.
Improper Permissions: Components may lack proper permissions, compromising security.
WebView Vulnerabilities: WebViews embedded in apps may have security flaws.
Network Security Configuration: Inadequate network security settings can lead to insecure communication.
Hardcoded Credentials: Developers sometimes embed credentials directly in the code.
Improper Input Validation: Lack of input validation can lead to injection attacks.
Hidden Features: Apps may contain unintended functionality or backdoors.
Insecure Storage: Storing sensitive data insecurely poses risks234.
