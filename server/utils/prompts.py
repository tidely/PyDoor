""" Commonly used prompts """


def increase_timeout_prompt():
    """ Prompt user to increase timeout limit """
    print('Client did not respond in time.')
    choice = input('Do you want to remove the timeout? ')
    if choice.strip().lower().startswith('y'):
        return True

    return False
