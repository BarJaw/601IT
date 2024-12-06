# CloudTrail Events Analyzer

## Description
This project is designed to analyze AWS CloudTrail event history for specific enumeration and persistence events. It uses AWS SDK for Python (Boto3) to interact with AWS services and retrieve event history.


## Installation
1. Clone the repository:
    ```sh
    git clone <repository-url>
    ```
2. Navigate to the project directory:
    ```sh
    cd <project-directory>
    ```
3. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage
1. Run the application:
    ```sh
    python app.py --regions REGIONS --profile PROFILE --token TOKEN --start-time START_TIME --end-time END_TIME

2. The application will prompt you to log in using AWS SSO and will retrieve the event history for the specified user.


## Contributing
1. Fork the repository.
2. Create a new branch:
    ```sh
    git checkout -b feature-branch
    ```
3. Make your changes and commit them:
    ```sh
    git commit -m "Description of changes"
    ```
4. Push to the branch:
    ```sh
    git push origin feature-branch
    ```
5. Open a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.