# Log Book - Semester Project 1 (2025-26)
This is a progress log detailing the work done on our semester project.

## Index

1. *Week 01:* Group Establishment (28/07/2025 - 02/08/2025)
2. *Week 02:* Topic Selection (04/08/2025 - 16/08/2025)
3. *Week 03:* Requirements Analysis & System Overview (18/08/2025 - 23/08/2025)
4. *Week 04:* System Architecture Design (28/08/2025 - 02/09/2025)
5. *Week 05:* Phase I of Implementation (03/09/2025 - 13/09/2025)
6. *Week 06:* Combined Design & Implementation (15/09/2025 - 20/09/2025)
7. *Week 07:* Phase II of Implementation (22/09/2025 - 04/10/2025)
8. *Week 08:* Phase III of Implementation (06/10/2025 - 18/10/2025)
9. *Week 09:* System Testing (29/10/2025 - 01/11/2025)
10. *Week 10:* Final Results & Analysis (03/11/2025 - 08/11/2025)
11. *Week 11:* Final Report & Conclusion (10/11/2025 - 15/11/2025)

---

### Week 1: Group Establishment
*Date:* 28/07/2025 - 02/08/2025
* *Activities Completed:*
    * Formed project group of 5 members and assigned roles (UI design, Backend, Database, Documentation).
    * Discussed project objective: Developing a system to store medical records digitally using QR codes.
    * Created GitHub repository to store all project files and track progress.
* *Next Plan:* Finalize the project topic and perform existing system survey.
* *Guide Interaction:* Initial discussion with guide regarding the hospital management domain and team structure.

### Week 2: Topic Selection
*Date:* 04/08/2025 - 16/08/2025
* *Activities Completed:*
    * Finalized topic: 'Document Storing Management System Using QR Code For Hospital'.
    * Defined key goals: Reduce paper usage, prevent loss of reports, and provide quick access via QR.
    * Conducted survey of existing paper-based systems and identified limitations.
* *Next Plan:* Start requirement analysis and identify modules.
* *Guide Interaction:* Guide approved the topic and emphasized the importance of data security in hospital systems.

### Week 3: Requirements Analysis & System Overview
*Date:* 18/08/2025 - 23/08/2025
* *Activities Completed:*
    * Identified three main modules: Admin, Patient, and Doctor.
    * Defined functional requirements: Document Upload, QR Code Generation, and Profile Management.
    * Selected software requirements: Windows 10, Google Chrome, and QR Code Libraries.
* *Next Plan:* Design system architecture and database schema.
* *Guide Interaction:* Guide reviewed the module breakdown and suggested adding specific roles for doctors to scan codes.

### Week 4: System Architecture Design
*Date:* 28/08/2025 - 02/09/2025
* *Activities Completed:*
    * Designed System Architecture: Frontend (HTML/CSS/JS) -> Backend (Node.js) -> Database (PostgreSQL via Neon Console).
    * Planned the data flow for how a patient uploads a file and receives a QR code.
    * Designed database schema in Neon Console to link Patient IDs with Document URLs and QR codes.
* *Next Plan:* Begin Phase 1 Implementation: UI and Database setup.
* *Guide Interaction:* Guide validated the technology stack (Node.js + Neon PostgreSQL) and architecture flow.

### Week 5: Phase I of Implementation
*Date:* 03/09/2025 - 13/09/2025
* *Activities Completed:*
    * Set up the project environment with Node.js and Express.
    * Created a PostgreSQL database instance on Neon Console.
    * Developed the 'Patient Registration' and 'Login' pages using HTML and CSS and connected to Neon DB.
* *Next Plan:* Implement backend logic for user authentication.
* *Guide Interaction:* Guide reviewed the UI designs for the registration forms and suggested including blood group details.

### Week 6: Combined Design & Implementation
*Date:* 15/09/2025 - 20/09/2025
* *Activities Completed:*
    * Connected Frontend forms with Backend Node.js APIs.
    * Implemented 'Patient Dashboard' where users can view their profile.
    * Tested basic database connectivity to Neon Console and user data insertion.
* *Next Plan:* Implement Document Upload and QR Code generation.
* *Guide Interaction:* Guide reviewed backend connectivity and advised on handling server-side errors.

### Week 7: Phase II of Implementation
*Date:* 22/09/2025 - 04/10/2025
* *Activities Completed:*
    * Developed 'Document Upload Module' allowing patients to upload PDFs/Images.
    * Integrated 'QR Code Library' to generate unique codes upon successful upload.
    * Ensured files are securely stored and linked to the specific patient ID in the database.
* *Next Plan:* Implement the Doctor's scanning and viewing module.
* *Guide Interaction:* Guide reviewed the QR generation process and suggested verifying the scanning speed.

### Week 8: Phase III of Implementation
*Date:* 06/10/2025 - 18/10/2025
* *Activities Completed:*
    * Finalized the 'Doctor Module' to allow scanning and viewing reports.
    * Implemented the 'Admin Module' to manage users and control system access.
    * Added password protection logic so only authorized persons can view files after scanning.
* *Next Plan:* Start full-system testing and deployment preparation.
* *Guide Interaction:* Guide reviewed the security features (Password + QR) and approved the module integration.

### Week 9: System Testing
*Date:* 29/10/2025 - 01/11/2025
* *Activities Completed:*
    * Deployed the complete application online using Render Dashboard.
    * Performed Unit Testing on Login, Registration, and Upload functions on the live Render link.
    * Tested the QR Code scanning flow using mobile devices.
* *Next Plan:* Analyze results and prepare documentation.
* *Guide Interaction:* Guide advised testing the system on different networks to ensure Render deployment stability.

### Week 10: Final Results & Analysis
*Date:* 03/11/2025 - 08/11/2025
* *Activities Completed:*
    * Analyzed system efficiency: Quick access to records vs paper-based search.
    * Captured screenshots of the working system (Render Dashboard, Neon Console, UI) for the report.
    * Confirmed the system meets objectives: Paperless and Eco-friendly.
* *Next Plan:* Draft the final report and conclusion.
* *Guide Interaction:* Guide reviewed the final results and screenshots, suggesting improvements for the conclusion section.

### Week 11: Final Report & Conclusion
*Date:* 10/11/2025 - 15/11/2025
* *Activities Completed:*
    * Compiled the Final Report: Introduction, Modules, Tech Stack (Neon, Render, Node.js), and Conclusion.
    * Documented the Future Scope (Cloud integration, Mobile App).
    * Finalized the Logbook and prepared for the project demonstration.
* *Next Plan:* Submit project and prepare for viva.
* *Guide Interaction:* Guide appreciated the completed system and 'Secure Hospital Document System' implementation.
