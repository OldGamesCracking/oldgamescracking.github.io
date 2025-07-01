/* Private Includes */
#include "mod_list.h"


MOD_t* mod_list_add(MOD_t *list, DWORD Base, DWORD Size)
{
	MOD_t *next = (MOD_t*)malloc(sizeof(MOD_t));
	next->Base = Base;
	next->Size = Size;
	next->End = Base + Size;
	next->Next = NULL;

	if (list == NULL)
	{
		/* Empty list */
		return next;
	}

	if (Base <= list->Base)
	{
		/* Smallest Base so far */

		next->Next = list;

		return next;
	}

	MOD_t *head = list;

	while (head->Next != NULL)
	{
		if ((head->Base <= Base) && (Base <= head->Next->Base))
		{
			/* Sort into list */
			next->Next = head->Next;
			head->Next = next;

			return list;
		}

		head = head->Next;
	}

	/* Largest Base so far */
	head->Next = next;

	return list;
}

BOOL mod_list_is_in(MOD_t *list, DWORD address)
{
	MOD_t* head = list;

	while (head != NULL)
	{
		if (head->Base <= address)
		{
			if (address < head->End)
			{
				return TRUE;
			}
		}
		else
		{
			/* All other bases will be larger */
			return FALSE;
		}

		head = head->Next;
	}

	return FALSE;
}

void mod_list_free(MOD_t *list)
{
	MOD_t *head = list;

	while (head != NULL)
	{
		list = head;
		head = head->Next;

		free(list);
	}
}