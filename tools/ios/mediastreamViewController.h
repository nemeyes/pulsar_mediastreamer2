/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
 *
 * This file is part of mediastreamer2 
 * (see https://gitlab.linphone.org/BC/public/mediastreamer2).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
//
//  mediastreamViewController.h
//  mediastream
//
//  Created by jehan on 15/06/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface mediastreamViewController : UIViewController {
    UIView* portraitImageView;
	UIView* portraitPreview;
	UIView* landscapeImageView;
	UIView* landscapePreview;
	UIView* portrait;
	UIView* landscape;
	}


@property (nonatomic, retain) IBOutlet UIView* portraitImageView;
@property (nonatomic, retain) IBOutlet UIView* portraitPreview;	
@property (nonatomic, retain) IBOutlet UIView* landscapeImageView;
@property (nonatomic, retain) IBOutlet UIView* landscapePreview;	
@property (nonatomic, retain) IBOutlet UIView* portrait;
@property (nonatomic, retain) IBOutlet UIView* landscape;	
@end
