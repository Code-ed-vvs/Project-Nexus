import openai

# Set your OpenAI API key
openai.api_key = "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"


def analyze_response(problem_description, student_response):
    """
    Analyze the student's response for spam and relevance.
    Args:
        problem_description (str): The problem description provided by the company.
        student_response (str): The student's response to the problem.
    Returns:
        dict: Contains spam status, relevance score, and analysis summary.
    """
    prompt = (
        f"Problem Description: {problem_description}\n\n"
        f"Student's Response: {student_response}\n\n"
        "Tasks:\n"
        "1. Check if the student's response contains inappropriate language or is spam. "
        "Respond with 'Spam' or 'Not Spam'.\n"
        "2. Evaluate how relevant the response is to the problem on a scale of 1 to 10, where 10 is highly relevant.\n"
        "3. Provide a brief explanation of your evaluation."
    )

    try:
        # Use gpt-3.5-turbo model for text completion
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Use gpt-3.5-turbo model
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.7
        )

        output = response['choices'][0]['message']['content'].strip().split("\n")

        # Initialize variables for spam status and relevance score
        spam_status = ""
        relevance_score = 0
        analysis_summary = ""

        # Extract Spam Status
        if output[0].startswith("Spam:"):
            spam_status = output[0].split(":")[-1].strip()

        # Extract Relevance Score (Handling cases where extra text might appear)
        for line in output:
            if line.lower().startswith("relevance score"):
                relevance_score = int(line.split(":")[-1].strip().split()[0])  # Extract just the number

        # Extract remaining analysis summary
        analysis_summary = " ".join([line for line in output if line.lower() not in ["spam:", "relevance score:"]])

        return {
            "spam_status": spam_status,
            "relevance_score": relevance_score,
            "analysis_summary": analysis_summary
        }
    except Exception as e:
        return {"error": str(e)}


# Main function
if __name__ == "__main__":
    print("=== ChatGPT Spam and Relevance Checker ===")

    # Input the problem description and student's response
    problem_description = input("Enter the problem description provided by the company: ")
    student_response = input("Enter the student's response to the problem: ")

    # Analyze the response
    result = analyze_response(problem_description, student_response)

    # Display the results
    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print("\n--- Analysis Result ---")
        print(f"Spam Status: {result['spam_status']}")
        print(f"Relevance Score: {result['relevance_score']}/10")
        print(f"Analysis Summary: {result['analysis_summary']}")