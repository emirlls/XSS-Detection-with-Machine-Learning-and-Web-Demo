from xss import *
import streamlit as st

st.title("XSS DETECTION PROJECT WEB DEMO")
# Kullanıcıdan input al
user_input = st.text_area("Enter to Check:")

# Verilen formata dönüştür
formatted_input = ["'" + user_input + "'" for user_input in user_input.split('\n')]

Xnew = getVec(formatted_input)
if st.button("CHECK", type="primary"):
    if user_input!="":
        #1 DecisionTreeClassifier
        ynew1 = loaded_model1.predict(Xnew)
        #2 SVC
        ynew2 = loaded_model2.predict(Xnew)
        #3 GaussianNB
        ynew3 = loaded_model3.predict(Xnew)
        #4 KNeighborsClassifier
        ynew4 = loaded_model4.predict(Xnew)
        #5 RandomForestClassifier
        ynew5 = loaded_model5.predict(Xnew)
        #6 MLPClassifier
        ynew6 = loaded_model6.predict(Xnew)
        #7 LogisticRegressionClassifier
        ynew7 = loaded_model7.predict(Xnew)  #YENİ EKLENDİ.

        # Initialize counts
        xssCount = 0
        notXssCount = 0

        # Display the detailed results
        st.write("\n*------------- RESULTS -------------*")
        for i in range(len(Xnew)):
            st.write(f"\n------------- Prediction for URL {i + 1} -------------")
            st.write(f"URL: {formatted_input[i]}")
            st.write(f"DecisionTreeClassifier Prediction: {ynew1[i]}")
            st.write(f"SVC Prediction: {ynew2[i]}")
            st.write(f"GaussianNB Prediction: {ynew3[i]}")
            st.write(f"KNeighborsClassifier Prediction: {ynew4[i]}")
            st.write(f"RandomForestClassifier Prediction: {ynew5[i]}")
            st.write(f"MLPClassifier Prediction: {ynew6[i]}")
            st.write(f"LogisticRegression Prediction: {ynew7[i]}")

            # Calculate the overall score based on your scoring logic
            score = (
                0.175 * ynew1[i]
                + 0.15 * ynew2[i]
                + 0.05 * ynew3[i]
                + 0.075 * ynew4[i]
                + 0.25 * ynew5[i]
                + 0.3 * ynew6[i]
                + 0.2 * ynew7[i]  # Eklendiği kısım
            )
            st.write(f"Overall Score: {score}")

            if score >= 0.5:
                st.write("XSS Detected")
                xssCount += 1  # XSS sayısını güncelle
            else:
                st.write("XSS Not Detected")
                notXssCount += 1  # NOT XSS sayısını güncelle
        
    else:
        st.write("Please Enter the URL")

    # Calculate the total counts
    st.write("\n*------------- SUMMARY -------------*")
    st.write(f'XSS Detected in {xssCount} URLs')
    st.write(f'XSS Not Detected in {notXssCount} URLs')
