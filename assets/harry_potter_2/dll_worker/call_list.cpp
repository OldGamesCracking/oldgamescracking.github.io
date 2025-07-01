/* Private Includes */
#include "calls_list.h"


CALL_t* call_list_add(CALL_t *list, DWORD CallAt, DWORD Target, SIZE_T InstructionLen, BOOL IsTrampoline)
{
	CALL_t *next = (CALL_t*)malloc(sizeof(CALL_t));
	next->CallAt = CallAt;
	next->Target = Target;
	next->InstructionLen = InstructionLen;
	next->Next = NULL;

	next->IsTrampoline = IsTrampoline;

	if (list == NULL)
	{
		/* Empty list */
		return next;
	}

	if (Target <= list->Target)
	{
		/* Smallest Target so far */

		next->Next = list;

		return next;
	}

	CALL_t *head = list;

	while (head->Next != NULL)
	{
		if ((head->Target <= Target) && (Target <= head->Next->Target))
		{
			/* Sort into list */
			next->Next = head->Next;
			head->Next = next;

			return list;
		}

		head = head->Next;
	}

	/* Largest Target so far */
	head->Next = next;

	return list;
}

void call_list_free(CALL_t *list)
{
	CALL_t *head = list;

	while (head != NULL)
	{
		list = head;
		head = head->Next;

		free(list);
	}
}