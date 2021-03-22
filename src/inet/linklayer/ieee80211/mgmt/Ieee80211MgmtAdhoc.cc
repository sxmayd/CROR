//
// Copyright (C) 2006 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/linklayer/ieee80211/mgmt/Ieee80211MgmtAdhoc.h"
#include "inet/linklayer/common/Ieee802Ctrl.h"

namespace inet {

namespace ieee80211 {

Define_Module(Ieee80211MgmtAdhoc);

void Ieee80211MgmtAdhoc::initialize(int stage)
{
    Ieee80211MgmtBase::initialize(stage);

    // Local frequency initialize
    bool f0 = par("freqListLocal_0").boolValue();
    bool f1 = par("freqListLocal_1").boolValue();
    bool f2 = par("freqListLocal_2").boolValue();
    freqUsingLocal = par("freqUsingLocal");
    attackStartTime = par("attackStartTime");
    freqListLocal[0] = f0;
    freqListLocal[1] = f1;
    freqListLocal[2] = f2;
    WATCH(freqListLocal[0]);
    WATCH(freqListLocal[1]);
    WATCH(freqListLocal[2]);
    WATCH(freqUsingLocal);

    // @myd
    clkmsg = new cMessage("CLK_MSG");
    clkmsg->setKind(FREQ_HOP_MSG);
    attcmsg = new cMessage("ATTACK_START");
    attcmsg->setKind(ATTACK_START);
    delay = 1.0;

    scheduleAt(attackStartTime, attcmsg);
}

void Ieee80211MgmtAdhoc::handleTimer(cMessage *msg)
{
    //ASSERT(false);
    if(msg->getKind() == FREQ_HOP_MSG){
        EV << "--------------------------------------------Timer Out------------------------------------------" << endl;
        //TODO  frequency hopping operation! @myd
        EV << "can not receive any msg for a certain time, the old frequency may be attacked, ao hop to a new one according to dict." << endl;
        freqUsingLocal = 2;
    }
    if(msg->getKind() == ATTACK_START){
        freqListLocal[0] = 1;
    }
}

void Ieee80211MgmtAdhoc::handleUpperMessage(cPacket *msg)
{
    Ieee80211DataFrame *frame = encapsulate(msg);
    EV_INFO << "msg has been encapsulated! @myd" << endl; //will be done before get to mac.cc
    sendDown(frame);
}

void Ieee80211MgmtAdhoc::handleCommand(int msgkind, cObject *ctrl)
{
    throw cRuntimeError("handleCommand(): no commands supported");
}

Ieee80211DataFrame *Ieee80211MgmtAdhoc::encapsulate(cPacket *msg)
{
    Ieee80211DataFrameWithSNAP *frame = new Ieee80211DataFrameWithSNAP(msg->getName());

    // copy receiver address from the control info (sender address will be set in MAC)
    Ieee802Ctrl *ctrl = check_and_cast<Ieee802Ctrl *>(msg->removeControlInfo());
    frame->setReceiverAddress(ctrl->getDest());
    frame->setEtherType(ctrl->getEtherType());

    // update the local freqList to message which is to send! @myd
    for(int i = 0; i < freqNum; i++){
        frame->setFreqListMsg(i,freqListLocal[i]);
        EV << "---------------------------We are setting the freq msg to pkt! ----------------------------" << endl;
    }

    // to check if the frequency using now is attacked, if true, hop the frequency @myd
    if(freqListLocal[freqUsingLocal] == true){
        freqUsingLocal = 2;
    }

    frame->setFreq_using(freqUsingLocal);

    int up = ctrl->getUserPriority();
    if (up >= 0) {
        // make it a QoS frame, and set TID
        frame->setType(ST_DATA_WITH_QOS);
        frame->addBitLength(QOSCONTROL_BITS);
        frame->setTid(up);
    }
    delete ctrl;

    frame->encapsulate(msg);
    return frame;
}

cPacket *Ieee80211MgmtAdhoc::decapsulate(Ieee80211DataFrame *frame)
{
    cPacket *payload = frame->decapsulate();

    Ieee802Ctrl *ctrl = new Ieee802Ctrl();
    ctrl->setSrc(frame->getTransmitterAddress());
    ctrl->setDest(frame->getReceiverAddress());
    int tid = frame->getTid();
    if (tid < 8)
        ctrl->setUserPriority(tid); // TID values 0..7 are UP
    Ieee80211DataFrameWithSNAP *frameWithSNAP = dynamic_cast<Ieee80211DataFrameWithSNAP *>(frame);
    if (frameWithSNAP)
        ctrl->setEtherType(frameWithSNAP->getEtherType());
    payload->setControlInfo(ctrl);


    // TODO to check if the frequency of the pkt using is same to local frequency @myd
    if(frame->getFreq_using() != freqUsingLocal){
        // drop the pkt(aka. not receive the pkt)
        EV << "frequency is been attacked(aka. transmitter has hop the frequency), drop the pkt----------------------------------------------" << endl;
        return NULL;
    }
    else{
        // only when the frequency is consistent, freqListLocal will be update @myd
        for(int i = 0; i < freqNum; i++){
            freqListLocal[i] |= frame->getFreqListMsg(i); // here '|=' is important for simulation @myd
        }
    }

    delete frame;
    return payload;
}

void Ieee80211MgmtAdhoc::handleDataFrame(Ieee80211DataFrame *frame)
{
    cPacket* payload;
    payload = decapsulate(frame);
    if(!payload){
        //TODO nothing
    }
    if(payload){
        if(clkmsg->isScheduled())
            cancelEvent(clkmsg);

        // to get current simulation time (aka. the time of last pkt arrive) @myd
        t_lastpkt = simTime();

        scheduleAt(t_lastpkt + 2 * delay, clkmsg);

        sendUp(payload);
    }

}

void Ieee80211MgmtAdhoc::handleAuthenticationFrame(Ieee80211AuthenticationFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleDeauthenticationFrame(Ieee80211DeauthenticationFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleAssociationRequestFrame(Ieee80211AssociationRequestFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleAssociationResponseFrame(Ieee80211AssociationResponseFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleReassociationRequestFrame(Ieee80211ReassociationRequestFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleReassociationResponseFrame(Ieee80211ReassociationResponseFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleDisassociationFrame(Ieee80211DisassociationFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleBeaconFrame(Ieee80211BeaconFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleProbeRequestFrame(Ieee80211ProbeRequestFrame *frame)
{
    dropManagementFrame(frame);
}

void Ieee80211MgmtAdhoc::handleProbeResponseFrame(Ieee80211ProbeResponseFrame *frame)
{
    dropManagementFrame(frame);
}

} // namespace ieee80211

} // namespace inet

