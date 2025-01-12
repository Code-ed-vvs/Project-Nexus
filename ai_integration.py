import openai
import json
from config import OPENAI_API_KEY

# Setup OpenAI API key
openai.api_key = f"{OPENAI_API_KEY}"

def analyze_solution(problem_title, problem_description, solution_text):
    """
    Analyze a solution using GPT to evaluate its relevance and quality.
    Returns a score and detailed feedback.
    """
    try:
        prompt = f"""
        As an AI evaluator for technical solutions, analyze this solution based on the following criteria:
        
        Problem:
        Title: {problem_title}
        Description: {problem_description}
        
        Proposed Solution:
        {solution_text}
        
        Please evaluate the solution on these criteria:
        1. Relevance (1-10): How well does it address the specific problem?
        2. Technical Merit (1-10): How technically sound and feasible is the solution?
        3. Innovation (1-10): How innovative or creative is the approach?
        4. Completeness (1-10): How comprehensive is the solution?
        5. Implementation Clarity (1-10): How clear and well-explained is the implementation?
        
        Provide your evaluation in the following JSON format:
        {{
            "scores": {{
                "relevance": x,
                "technical_merit": x,
                "innovation": x,
                "completeness": x,
                "implementation_clarity": x,
                "overall_score": x
            }},
            "feedback": {{
                "strengths": ["point1", "point2"],
                "weaknesses": ["point1", "point2"],
                "suggestions": ["point1", "point2"]
            }}
        }}
        """

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an expert technical evaluator specializing in analyzing solutions to complex technical problems."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )

        # Parse the response
        evaluation = json.loads(response.choices[0].message.content)
        
        # Calculate overall score if not provided
        if 'overall_score' not in evaluation['scores']:
            scores = evaluation['scores']
            overall_score = sum(scores.values()) / len(scores)
            evaluation['scores']['overall_score'] = round(overall_score, 2)

        return evaluation

    except Exception as e:
        print(f"Error in AI analysis: {str(e)}")
        return {
            "scores": {
                "relevance": 0,
                "technical_merit": 0,
                "innovation": 0,
                "completeness": 0,
                "implementation_clarity": 0,
                "overall_score": 0
            },
            "feedback": {
                "strengths": ["Error in AI analysis"],
                "weaknesses": ["Unable to evaluate solution"],
                "suggestions": ["Please try again later"]
            }
        }

def get_solution_rank(all_solutions_scores):
    """
    Rank solutions based on their overall scores.
    Returns a list of tuples (solution_id, rank).
    """
    # Sort solutions by overall score in descending order
    ranked_solutions = sorted(
        [(sol_id, scores['overall_score']) for sol_id, scores in all_solutions_scores.items()],
        key=lambda x: x[1],
        reverse=True
    )
    
    # Assign ranks (handling ties)
    current_rank = 1
    current_score = None
    ranks = []
    
    for i, (sol_id, score) in enumerate(ranked_solutions):
        if score != current_score:
            current_rank = i + 1
            current_score = score
        ranks.append((sol_id, current_rank))
    
    return dict(ranks)

def summarize_solutions(problem_title, problem_description, solutions):
    """
    Generate a summary of all solutions for a problem.
    """
    try:
        solutions_text = "\n".join([f"Solution {i+1}: {sol['text']}" for i, sol in enumerate(solutions)])
        
        prompt = f"""
        Problem:
        Title: {problem_title}
        Description: {problem_description}
        
        Solutions Submitted:
        {solutions_text}
        
        Please provide a comprehensive analysis of all submitted solutions:
        1. Identify common themes and approaches
        2. Compare and contrast different solutions
        3. Highlight the most promising ideas
        4. Suggest potential combinations of different approaches
        
        Format your response in JSON:
        {{
            "common_themes": ["theme1", "theme2"],
            "unique_approaches": ["approach1", "approach2"],
            "most_promising_ideas": ["idea1", "idea2"],
            "synthesis_suggestions": ["suggestion1", "suggestion2"],
            "overall_summary": "brief summary text"
        }}
        """

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an expert at analyzing and synthesizing technical solutions."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )

        return json.loads(response.choices[0].message.content)

    except Exception as e:
        print(f"Error in solutions summary: {str(e)}")
        return {
            "common_themes": ["Error in analysis"],
            "unique_approaches": [],
            "most_promising_ideas": [],
            "synthesis_suggestions": [],
            "overall_summary": "Error generating summary"
        }

def analyze_response(problem_description, student_response):
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
            model="gpt-3.5-turbo",
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

    # Input the problem title, problem description, and solution text
    problem_title = input("Enter the problem title: ")
    problem_description = input("Enter the problem description: ")
    solution_text = input("Enter the solution text: ")

    # Analyze the solution
    solution_result = analyze_solution(problem_title, problem_description, solution_text)

    # Display the solution analysis results
    print("\n--- Solution Analysis Result ---")
    print(f"Scores: {solution_result['scores']}")
    print(f"Feedback: {solution_result['feedback']}")

    # Input multiple solutions
    num_solutions = int(input("Enter the number of solutions: "))
    solutions = []
    for i in range(num_solutions):
        solution_text = input(f"Enter solution {i+1} text: ")
        solutions.append({"text": solution_text})

    # Summarize the solutions
    summary_result = summarize_solutions(problem_title, problem_description, solutions)

    # Display the solutions summary results
    print("\n--- Solutions Summary Result ---")
    print(f"Common Themes: {summary_result['common_themes']}")
    print(f"Unique Approaches: {summary_result['unique_approaches']}")
    print(f"Most Promising Ideas: {summary_result['most_promising_ideas']}")
    print(f"Synthesis Suggestions: {summary_result['synthesis_suggestions']}")
    print(f"Overall Summary: {summary_result['overall_summary']}")

    # Rank the solutions
    solution_scores = {}
    for i, solution in enumerate(solutions):
        solution_scores[f"solution_{i+1}"] = analyze_solution(problem_title, problem_description, solution["text"])["scores"]
    ranked_solutions = get_solution_rank(solution_scores)

    # Display the ranked solutions
    print("\n--- Ranked Solutions ---")
    for solution_id, rank in ranked_solutions.items():
        print(f"{solution_id}: {rank}")
