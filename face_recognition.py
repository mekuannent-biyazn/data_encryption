import cv2

def recognize_face():
    # Load the pre-trained Haar Cascade classifier for face detection
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    # Load the captured face image
    user_face = cv2.imread('user_face.jpg')
    user_face_gray = cv2.cvtColor(user_face, cv2.COLOR_BGR2GRAY)

    # Start video capture
    cap = cv2.VideoCapture(0)

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Convert the frame to grayscale
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Detect faces in the frame
        faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5)

        for (x, y, w, h) in faces:
            # Draw a rectangle around the detected face
            cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)

            # Extract the face region
            detected_face = gray_frame[y:y + h, x:x + w]

            # Compare with the stored user face (you can implement a more sophisticated comparison)
            if cv2.norm(user_face_gray, detected_face, cv2.NORM_L2) < 10000:  # Adjust threshold as needed
                cv2.putText(frame, "Unlocked", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
            else:
                cv2.putText(frame, "Locked", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 255), 2)

        # Display the frame
        cv2.imshow('Face Recognition', frame)

        # Break the loop on 'q' key press
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    recognize_face()
