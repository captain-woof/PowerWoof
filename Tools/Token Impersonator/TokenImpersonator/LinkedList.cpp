#include "LinkedList.h"

struct _Node {
    LPVOID ElementP;
    _Node* NextNodeP;
};

LinkedList::LinkedList() {
    Head = NULL;
    Rear = NULL;
    CurrentNodeP = NULL;
    TempNodeP = NULL;
    Size = 0;
    CurrentIndex = 0;
    CleanUpElementsRequired = true;
}

void LinkedList::Clear() {
    if (GetSize() != 0) {
        while (GetSize() != 0) {
            Remove(GetSize() - 1);
        }
    }
}

void LinkedList::SetCleanUpRequired(BOOL CleanUpElements) {
    CleanUpElementsRequired = CleanUpElements;
}

BOOL LinkedList::Remove(int IndexToDeleteAt) {
    if (IsIndexValid(IndexToDeleteAt)) {
        PNode PrecedingNode, ToRemoveNode;

        if (IndexToDeleteAt == 0) {
            ToRemoveNode = Head;
            Head = Head->NextNodeP;
        }
        else {
            PrecedingNode = GetNodeP(IndexToDeleteAt - 1);
            ToRemoveNode = PrecedingNode->NextNodeP;
            PrecedingNode->NextNodeP = PrecedingNode->NextNodeP->NextNodeP;
        }

        if (CleanUpElementsRequired) {
            delete ToRemoveNode->ElementP;
        }
        delete ToRemoveNode;
        Size--;
        return true;
    }
    else {
        return false;
    }   
}

LinkedList::~LinkedList() {
    for (int i = 0; i < Size; i++) {
        TempNodeP = Head;
        Head = Head->NextNodeP;
        if (CleanUpElementsRequired) {
            delete TempNodeP->ElementP;
        }
        delete TempNodeP;
    }
}

BOOL LinkedList::Append(LPVOID ElementP) {
    TempNodeP = new Node;
    if (TempNodeP == NULL) {
        return false;
    }

    TempNodeP->ElementP = ElementP;
    TempNodeP->NextNodeP = NULL;

    if (!Size) { // Empty list            
        Head = TempNodeP;
        Rear = TempNodeP;
        CurrentNodeP = TempNodeP;
    }
    else { // Non-empty list
        Rear->NextNodeP = TempNodeP;
        Rear = TempNodeP;
    }
    Size++;
    return true;
}

LPVOID LinkedList::GetElementP(int TargetIndex) {
    if (IsIndexValid(TargetIndex)) {
        return (GetNodeP(TargetIndex))->ElementP;
    }
    else {
        return NULL;
    }
}

PNode LinkedList::GetNodeP(int TargetIndex) {
    if (IsIndexValid(TargetIndex)) {
        if (CurrentIndex > TargetIndex) {
            CurrentIndex = 0;
            CurrentNodeP = Head;
        }
        for (int i = CurrentIndex; i < TargetIndex; i++, CurrentIndex++) {
            CurrentNodeP = CurrentNodeP->NextNodeP;
        }
        return CurrentNodeP;
    }
    else {
        return NULL;
    }
}

BOOL LinkedList::Add(LPVOID ElementP, int IndexToAddAt) {
    if (IndexToAddAt == 0) {
        if (Append(ElementP)) {
            return true;
        }
        else {
            return false;
        }
    }

    if (IsIndexValid(IndexToAddAt)) {
        if (IndexToAddAt == Size - 1){
            if (Append(ElementP)) {
                return true;
            }
            else {
                return false;
            }
        }
        else{
            TempNodeP = new Node;
            if (TempNodeP == NULL) {
                return false;
            }
            TempNodeP->ElementP = ElementP;

            if (IndexToAddAt == 0) {
                TempNodeP->NextNodeP = Head;
                Head = TempNodeP;
            }
            else {
                PNode PrecedingNode = GetNodeP(IndexToAddAt - 1);
                TempNodeP->NextNodeP = PrecedingNode->NextNodeP;
                PrecedingNode->NextNodeP = TempNodeP;
            }
            Size++;
            return true;
        }
    }
    else {
        return false;
    }
}

BOOL LinkedList::IsIndexValid(int IndexToCheck) {
    if ((IndexToCheck >= Size) || (IndexToCheck < 0)) {
        return false;
    }
    else {
        return true;
    }
}

int LinkedList::GetSize() {
    return Size;
}