# Burp Suite Professional Report Generator Extension

This Burp Suite Professional extension helps penetration testers create detailed vulnerability reports in both PDF and Word formats.

## Features

- Create vulnerability reports based on OWASP Top 10 2021 categories
- Support for both PDF and Word report formats
- Customizable vulnerability details:
  - Description
  - Impact
  - Request/Response evidence
  - Custom remediation plans
  - Evidence screenshots
- Risk level classification
- Easy-to-use interface
- Image support in reports

## Installation

1. Download the latest JAR file from the releases page
2. In Burp Suite Professional, go to Extender > Extensions
3. Click "Add" button
4. Select the downloaded JAR file
5. The extension will be loaded and ready to use

## Usage

1. Right-click on any request in Burp Suite
2. Select "Add to Pentest Report"
3. Fill in the vulnerability details
4. Add screenshots or evidence if needed
5. Click "Add to Report"
6. Generate the final report in PDF or Word format

## Building from Source

1. Clone the repository
```bash
git clone https://github.com/yourusername/burp-report-generator.git
```

2. Build with Maven
```bash
mvn clean package
```

3. The JAR file will be created in the `target` directory

## Requirements

- Burp Suite Professional
- Java 8 or higher
- Maven (for building from source)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 